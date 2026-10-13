use anyhow::Result;
use lazy_static::lazy_static;
use log::{debug, info, warn};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

/// SOCKS5 握手各阶段统一 I/O 超时
const SOCKS5_IO_TIMEOUT: Duration = Duration::from_secs(5);

/// SOCKS5 服务器域名解析结果的缓存时长
///
/// 比通用 DNS 缓存短，DDNS 地址变化后最多这么久就会生效；
/// 连接失败时会立即清掉缓存，下次连接重新解析。
const SOCKS5_ADDR_CACHE_TTL: Duration = Duration::from_secs(60);

lazy_static! {
    // SOCKS5 服务器地址 -> (解析结果, 解析时间)
    static ref SOCKS5_ADDR_CACHE: Mutex<HashMap<String, (Vec<SocketAddr>, Instant)>> =
        Mutex::new(HashMap::new());
}

/// SOCKS5 代理配置
#[derive(Debug, Clone)]
pub struct Socks5Config {
    /// SOCKS5 代理服务器地址，格式：`ip:port`、`[ipv6]:port` 或 `domain:port`
    ///
    /// 域名在每次连接时解析（带短时缓存），因此支持 DDNS
    pub addr: String,
    /// 用户名（可选）
    pub username: Option<String>,
    /// 密码（可选）
    pub password: Option<String>,
}

/// 校验 SOCKS5 服务器地址格式（只检查格式，不做 DNS 解析）
pub fn validate_socks5_addr(addr: &str) -> Result<()> {
    if addr.parse::<SocketAddr>().is_ok() {
        return Ok(());
    }
    let (host, port) = addr
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("缺少端口号，格式应为 host:port"))?;
    if host.is_empty() || host.contains(':') {
        return Err(anyhow::anyhow!("无效的主机名: {}", host));
    }
    port.parse::<u16>()
        .map_err(|_| anyhow::anyhow!("无效的端口号: {}", port))?;
    Ok(())
}

/// 解析 SOCKS5 服务器地址：IP 直接返回，域名走短时缓存
async fn resolve_socks5_addr(addr: &str) -> Result<Vec<SocketAddr>> {
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        return Ok(vec![socket_addr]);
    }

    if let Some((addrs, resolved_at)) = SOCKS5_ADDR_CACHE.lock().unwrap().get(addr) {
        if resolved_at.elapsed() < SOCKS5_ADDR_CACHE_TTL {
            return Ok(addrs.clone());
        }
    }

    let addrs: Vec<SocketAddr> = match timeout(SOCKS5_IO_TIMEOUT, tokio::net::lookup_host(addr)).await {
        Ok(Ok(addrs)) => addrs.collect(),
        Ok(Err(e)) => return Err(anyhow::anyhow!("解析 SOCKS5 服务器地址 {} 失败: {}", addr, e)),
        Err(_) => return Err(anyhow::anyhow!("解析 SOCKS5 服务器地址 {} 超时", addr)),
    };
    if addrs.is_empty() {
        return Err(anyhow::anyhow!("SOCKS5 服务器地址 {} 解析结果为空", addr));
    }

    debug!("SOCKS5 服务器地址解析: {} -> {:?}", addr, addrs);
    SOCKS5_ADDR_CACHE
        .lock()
        .unwrap()
        .insert(addr.to_string(), (addrs.clone(), Instant::now()));
    Ok(addrs)
}

/// 依次尝试解析出的每个地址，全部失败时清掉缓存，下次连接重新解析
async fn connect_socks5_server(addr: &str) -> Result<TcpStream> {
    let mut last_err = None;
    for socket_addr in resolve_socks5_addr(addr).await? {
        match timeout(SOCKS5_IO_TIMEOUT, TcpStream::connect(socket_addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                last_err = Some(anyhow::anyhow!("无法连接到 SOCKS5 服务器 {} ({}): {}", addr, socket_addr, e));
            }
            Err(_) => {
                last_err = Some(anyhow::anyhow!("连接到 SOCKS5 服务器 {} ({}) 超时", addr, socket_addr));
            }
        }
    }

    if SOCKS5_ADDR_CACHE.lock().unwrap().remove(addr).is_some() {
        warn!("SOCKS5 服务器 {} 连接失败，已清除地址缓存", addr);
    }
    Err(last_err.unwrap_or_else(|| anyhow::anyhow!("无法连接到 SOCKS5 服务器 {}", addr)))
}

/// 优化的 SOCKS5 连接函数
///
/// 直接传递域名给 SOCKS5 服务器，让服务器端解析 DNS（避免客户端重复解析）
///
/// # 参数
/// * `target_host` - 目标主机名
/// * `target_port` - 目标端口
/// * `socks5_config` - SOCKS5 配置
///
/// # 返回
/// 连接到目标的 TcpStream
pub async fn connect_via_socks5(
    target_host: &str,
    target_port: u16,
    socks5_config: &Socks5Config,
) -> Result<TcpStream> {
    info!("通过 SOCKS5 连接到 {}:{}", target_host, target_port);

    // ============ 步骤 1: 连接到 SOCKS5 服务器 ============
    let mut socks5_stream = connect_socks5_server(&socks5_config.addr).await?;

    let _ = socks5_stream.set_nodelay(true);

    // ⚡ 优化：设置 socket 选项以提升性能
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = socks5_stream.as_raw_fd();
        unsafe {
            // 设置 TCP_QUICKACK（Linux）- 快速 ACK
            #[cfg(target_os = "linux")]
            {
                const TCP_QUICKACK: libc::c_int = 12;
                let quickack: libc::c_int = 1;
                let _ = libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    TCP_QUICKACK,
                    &quickack as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&quickack) as libc::socklen_t,
                );
            }
        }
    }

    debug!("已连接到 SOCKS5 服务器: {}", socks5_config.addr);

    let mut request = Vec::new();
    request.push(5u8);  // SOCKS 版本 5

    // 认证方法：如果有用户名密码，使用用户名/密码认证（0x02），否则使用无认证（0x00）
    if socks5_config.username.is_some() && socks5_config.password.is_some() {
        request.push(1u8);  // 支持 1 种认证方法
        request.push(2u8);  // 用户名/密码认证
    } else {
        request.push(1u8);  // 支持 1 种认证方法
        request.push(0u8);  // 无认证
    }

    // 发送握手请求
    match timeout(
        SOCKS5_IO_TIMEOUT,
        socks5_stream.write_all(&request)
    ).await {
        Ok(Ok(())) => debug!("已发送 SOCKS5 握手请求"),
        Ok(Err(e)) => return Err(anyhow::anyhow!("写入 SOCKS5 握手请求失败: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("写入 SOCKS5 握手请求超时")),
    }

    // ============ 步骤 4: 读取握手响应 ============
    let mut response = [0u8; 2];
    match timeout(
        SOCKS5_IO_TIMEOUT,
        socks5_stream.read_exact(&mut response)
    ).await {
        Ok(Ok(n)) => {
            debug!("读取握手响应成功，字节数: {}", n)
        },
        Ok(Err(e)) => return Err(anyhow::anyhow!("读取 SOCKS5 握手响应失败: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("读取 SOCKS5 握手响应超时")),
    }

    if response[0] != 5 {
        return Err(anyhow::anyhow!("无效的 SOCKS5 响应: 版本错误"));
    }

    debug!("SOCKS5 握手成功，选择的认证方法: {}", response[1]);

    // ============ 步骤 5: 可选的认证步骤 ============
    if response[1] == 2 {
        // 用户名/密码认证
        if let (Some(username), Some(password)) = (&socks5_config.username, &socks5_config.password) {
            let mut auth_request = Vec::new();
            auth_request.push(1u8);  // 版本 1
            auth_request.push(username.len() as u8);
            auth_request.extend_from_slice(username.as_bytes());
            auth_request.push(password.len() as u8);
            auth_request.extend_from_slice(password.as_bytes());

            match timeout(
                SOCKS5_IO_TIMEOUT,
                socks5_stream.write_all(&auth_request)
            ).await {
                Ok(Ok(())) => debug!("已发送认证请求"),
                Ok(Err(e)) => return Err(anyhow::anyhow!("发送认证请求失败: {}", e)),
                Err(_) => return Err(anyhow::anyhow!("发送认证请求超时")),
            }

            let mut auth_response = [0u8; 2];
            match timeout(
                SOCKS5_IO_TIMEOUT,
                socks5_stream.read_exact(&mut auth_response)
            ).await {
                Ok(Ok(_)) => {},
                Ok(Err(e)) => return Err(anyhow::anyhow!("读取认证响应失败: {}", e)),
                Err(_) => return Err(anyhow::anyhow!("读取认证响应超时")),
            }

            if auth_response[1] != 0 {
                return Err(anyhow::anyhow!("SOCKS5 认证失败"));
            }
            debug!("SOCKS5 认证成功");
        }
    } else if response[1] != 0 {
        return Err(anyhow::anyhow!("不支持的认证方法: {}", response[1]));
    }

    // ============ 步骤 6: 发送连接请求 ============
    let mut connect_request = Vec::new();
    connect_request.push(5u8);   // SOCKS 版本 5
    connect_request.push(1u8);   // 连接命令 (CONNECT)
    connect_request.push(0u8);   // 保留字段

    // ⚡ 优化：直接使用域名，让 SOCKS5 服务器解析 DNS
    if target_host.len() > 255 {
        return Err(anyhow::anyhow!("域名太长: {}", target_host));
    }
    connect_request.push(0x03);  // 域名类型
    connect_request.push(target_host.len() as u8);  // 域名长度
    connect_request.extend_from_slice(target_host.as_bytes());  // 域名

    // 目标端口（网络字节序）
    connect_request.extend_from_slice(&target_port.to_be_bytes());

    match timeout(
        SOCKS5_IO_TIMEOUT,
        socks5_stream.write_all(&connect_request)
    ).await {
        Ok(Ok(())) => debug!("已发送 SOCKS5 连接请求"),
        Ok(Err(e)) => return Err(anyhow::anyhow!("发送 SOCKS5 连接请求失败: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("发送 SOCKS5 连接请求超时")),
    }

    // ============ 步骤 7: 读取连接响应 ============
    let mut response = [0u8; 4];
    match timeout(
        SOCKS5_IO_TIMEOUT,
        socks5_stream.read_exact(&mut response)
    ).await {
        Ok(Ok(_)) => {},
        Ok(Err(e)) => return Err(anyhow::anyhow!("读取 SOCKS5 连接响应失败: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("读取 SOCKS5 连接响应超时")),
    }

    if response[0] != 5 {
        return Err(anyhow::anyhow!("无效的 SOCKS5 响应: 版本错误"));
    }

    // 检查状态码
    match response[1] {
        0 => debug!("SOCKS5 连接成功"),
        1 => return Err(anyhow::anyhow!("SOCKS5: 一般 SOCKS 服务器故障")),
        2 => return Err(anyhow::anyhow!("SOCKS5: 连接规则集不允许的连接")),
        3 => return Err(anyhow::anyhow!("SOCKS5: 网络无法访问")),
        4 => return Err(anyhow::anyhow!("SOCKS5: 主机无法访问")),
        5 => return Err(anyhow::anyhow!("SOCKS5: 连接被拒绝")),
        6 => return Err(anyhow::anyhow!("SOCKS5: TTL 过期")),
        7 => return Err(anyhow::anyhow!("SOCKS5: 不支持的命令")),
        8 => return Err(anyhow::anyhow!("SOCKS5: 不支持的地址类型")),
        code => return Err(anyhow::anyhow!("SOCKS5: 未知错误代码 {}", code)),
    }

    // ============ 步骤 8: 读取剩余的响应数据 ============
    match response[3] {
        1 => {
            // IPv4: 需要读 4 个字节 IP + 2 个字节端口
            let mut addr_data = [0u8; 6];
            match timeout(
                SOCKS5_IO_TIMEOUT,
                socks5_stream.read_exact(&mut addr_data)
            ).await {
                Ok(Ok(_)) => {},
                Ok(Err(e)) => return Err(anyhow::anyhow!("读取地址数据失败: {}", e)),
                Err(_) => return Err(anyhow::anyhow!("读取地址数据超时")),
            }
            debug!("SOCKS5 连接响应 - IPv4 地址: {}.{}.{}.{}, 端口: {}",
                addr_data[0], addr_data[1], addr_data[2], addr_data[3],
                u16::from_be_bytes([addr_data[4], addr_data[5]])
            );
        }
        4 => {
            // IPv6: 需要读 16 个字节 IP + 2 个字节端口
            let mut addr_data = [0u8; 18];
            match timeout(
                SOCKS5_IO_TIMEOUT,
                socks5_stream.read_exact(&mut addr_data)
            ).await {
                Ok(Ok(_)) => {},
                Ok(Err(e)) => return Err(anyhow::anyhow!("读取地址数据失败: {}", e)),
                Err(_) => return Err(anyhow::anyhow!("读取地址数据超时")),
            }
            debug!("SOCKS5 连接响应 - IPv6 地址, 端口: {}",
                u16::from_be_bytes([addr_data[16], addr_data[17]])
            );
        }
        3 => {
            // 域名: 需要读 1 个字节长度 + N 个字节域名 + 2 个字节端口
            let mut len_buf = [0u8; 1];
            match timeout(
                SOCKS5_IO_TIMEOUT,
                socks5_stream.read_exact(&mut len_buf)
            ).await {
                Ok(Ok(_)) => {},
                Ok(Err(e)) => return Err(anyhow::anyhow!("读取域名长度失败: {}", e)),
                Err(_) => return Err(anyhow::anyhow!("读取域名长度超时")),
            }

            let domain_len = len_buf[0] as usize;
            if domain_len > 253 {
                return Err(anyhow::anyhow!("SOCKS5 响应中域名长度无效: {}", domain_len));
            }
            let mut domain_data = vec![0u8; domain_len + 2];
            match timeout(
                SOCKS5_IO_TIMEOUT,
                socks5_stream.read_exact(&mut domain_data)
            ).await {
                Ok(Ok(_)) => {},
                Ok(Err(e)) => return Err(anyhow::anyhow!("读取域名数据失败: {}", e)),
                Err(_) => return Err(anyhow::anyhow!("读取域名数据超时")),
            }

            let domain = String::from_utf8_lossy(&domain_data[..domain_len]);
            let port = u16::from_be_bytes([domain_data[domain_len], domain_data[domain_len + 1]]);
            debug!("SOCKS5 连接响应 - 域名: {}, 端口: {}", domain, port);
        }
        atyp => {
            return Err(anyhow::anyhow!("不支持的地址类型: {}", atyp));
        }
    }

    info!("✅ 通过 SOCKS5 成功连接到 {}:{}", target_host, target_port);
    Ok(socks5_stream)
}

#[cfg(test)]
mod addr_tests {
    use super::*;

    #[test]
    fn test_validate_socks5_addr() {
        assert!(validate_socks5_addr("127.0.0.1:1080").is_ok());
        assert!(validate_socks5_addr("[::1]:1080").is_ok());
        assert!(validate_socks5_addr("my.ddns.net:1080").is_ok());
        assert!(validate_socks5_addr("localhost:1080").is_ok());

        assert!(validate_socks5_addr("my.ddns.net").is_err());
        assert!(validate_socks5_addr(":1080").is_err());
        assert!(validate_socks5_addr("my.ddns.net:abc").is_err());
        assert!(validate_socks5_addr("my.ddns.net:70000").is_err());
        assert!(validate_socks5_addr("::1:1080").is_err());
    }

    #[tokio::test]
    async fn test_resolve_socks5_addr() {
        let addrs = resolve_socks5_addr("127.0.0.1:1080").await.unwrap();
        assert_eq!(addrs, vec!["127.0.0.1:1080".parse().unwrap()]);

        let addrs = resolve_socks5_addr("localhost:1080").await.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().all(|a| a.port() == 1080 && a.ip().is_loopback()));
        assert!(SOCKS5_ADDR_CACHE.lock().unwrap().contains_key("localhost:1080"));
    }
}
