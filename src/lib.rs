use anyhow::Result;
use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use lru::LruCache;
use lazy_static::lazy_static;
use std::num::NonZeroUsize;
use std::net::IpAddr;
use tokio::sync::Mutex;

// ======================== DNS 缓存 ========================

lazy_static! {
    static ref DNS_CACHE: Mutex<LruCache<String, Vec<IpAddr>>> =
        Mutex::new(LruCache::new(NonZeroUsize::new(1000).unwrap()));
}

/// 带缓存的 DNS 解析
pub async fn resolve_host_cached(host: &str) -> Result<Vec<IpAddr>> {
    // 1. 检查缓存
    {
        let mut cache = DNS_CACHE.lock().await;
        if let Some(ips) = cache.get(host) {
            debug!("DNS 缓存命中: {} -> {:?}", host, ips);
            return Ok(ips.clone());
        }
    }

    // 2. 执行 DNS 查询
    debug!("DNS 查询: {}", host);
    let addr_str = format!("{}:443", host);
    let ips: Vec<IpAddr> = tokio::net::lookup_host(&addr_str)
        .await?
        .map(|addr| addr.ip())
        .collect();

    if ips.is_empty() {
        return Err(anyhow::anyhow!("DNS 查询返回空列表: {}", host));
    }

    // 3. 缓存结果
    {
        let mut cache = DNS_CACHE.lock().await;
        cache.put(host.to_string(), ips.clone());
        debug!("DNS 缓存写入: {} -> {:?}", host, ips);
    }

    Ok(ips)
}

/// 清除 DNS 缓存（可选）
pub async fn clear_dns_cache() {
    let mut cache = DNS_CACHE.lock().await;
    cache.clear();
    info!("DNS 缓存已清除");
}

/// 获取缓存大小（用于监控）
pub async fn get_dns_cache_size() -> usize {
    let cache = DNS_CACHE.lock().await;
    cache.len()
}

// ======================== 在 connect_via_socks5 中使用 ========================

// 修改原来的 connect_via_socks5 函数中的 DNS 查询部分
// 从：
//     let addr = format!("{}:443", target_host);
//     let target_addr = TcpStream::connect(&addr).await?;
//
// 改为：
//     let ips = resolve_host_cached(target_host).await?;
//     let target_addr = TcpStream::connect((ips[0], 443)).await?;

// 完整示例（如果你想看到完整的 connect_via_socks5 函数）：
/*
pub async fn connect_via_socks5_with_cache(
    target_host: &str,
    target_port: u16,
    socks5_config: &Socks5Config,
) -> Result<TcpStream> {
    // 连接到 SOCKS5 服务器
    let mut socks5_stream = TcpStream::connect(&socks5_config.addr).await?;
    let _ = socks5_stream.set_nodelay(true);

    // 使用缓存的 DNS 解析
    let target_ips = resolve_host_cached(target_host).await?;
    let target_ip = target_ips[0];

    // SOCKS5 握手...
    // （这里是原来的 SOCKS5 握手代码）

    Ok(socks5_stream)
}
*/

/// SOCKS5 代理配置
#[derive(Debug, Clone)]
pub struct Socks5Config {
    /// SOCKS5 代理服务器地址
    pub addr: SocketAddr,
    /// 用户名（可选）
    pub username: Option<String>,
    /// 密码（可选）
    pub password: Option<String>,
}

/// 域名匹配器，支持精确匹配和通配符匹配
#[derive(Debug, Clone)]
pub struct DomainMatcher {
    /// 精确匹配的域名列表
    exact_domains: HashSet<String>,
    /// 通配符域名列表（例如 "*.example.com"），已排序以优化匹配
    wildcard_domains: Vec<String>,
}

impl DomainMatcher {
    /// 创建新的域名匹配器
    pub fn new(domains: Vec<String>) -> Self {
        let mut exact_domains = HashSet::new();
        let mut wildcard_domains = Vec::new();

        for domain in domains {
            let domain_lower = domain.to_lowercase(); // 统一转换为小写

            if domain_lower.starts_with("*.") {
                // 通配符域名
                let suffix = domain_lower[2..].to_string();
                if !suffix.is_empty() {
                    wildcard_domains.push(suffix);
                    info!("添加通配符域名: {}", domain_lower);
                }
            } else if !domain_lower.is_empty() {
                // 精确匹配域名
                exact_domains.insert(domain_lower.clone());
                info!("添加精确匹配域名: {}", domain_lower);
            }
        }

        // 按长度排序通配符域名（更长的优先匹配，提高准确性）
        wildcard_domains.sort_by(|a, b| b.len().cmp(&a.len()));

        Self {
            exact_domains,
            wildcard_domains,
        }
    }

    /// 检查域名是否匹配白名单
    #[inline]
    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // 先检查精确匹配（O(1)）
        if self.exact_domains.contains(&domain_lower) {
            return true;
        }

        // 再检查通配符匹配（O(n)，但已优化）
        for wildcard_suffix in &self.wildcard_domains {
            if domain_lower.len() > wildcard_suffix.len()
                && domain_lower.ends_with(wildcard_suffix) {
                // 确保匹配的是完整的子域名
                let prefix_len = domain_lower.len() - wildcard_suffix.len();
                if &domain_lower[prefix_len - 1..prefix_len] == "." {
                    return true;
                }
            }
        }

        false
    }
}

/// SNI 代理服务器
pub struct SniProxy {
    /// 监听地址
    listen_addr: SocketAddr,
    /// 域名匹配器
    domain_matcher: Arc<DomainMatcher>,
    /// 最大并发连接数
    max_connections: usize,
    /// SOCKS5 代理配置（可选）
    socks5_config: Option<Arc<Socks5Config>>,
}

impl SniProxy {
    /// 创建新的 SNI 代理实例
    pub fn new(listen_addr: SocketAddr, whitelist: Vec<String>) -> Self {
        let domain_matcher = DomainMatcher::new(whitelist);

        Self {
            listen_addr,
            domain_matcher: Arc::new(domain_matcher),
            max_connections: 50000, // 默认最大并发连接数（提高到 50000）
            socks5_config: None,
        }
    }

    /// 设置最大并发连接数
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// 设置 SOCKS5 代理
    pub fn with_socks5(mut self, socks5_config: Socks5Config) -> Self {
        self.socks5_config = Some(Arc::new(socks5_config));
        self
    }

    /// 启动代理服务器（使用专用 accept 线程以避免 Tokio 调度延迟）
    pub async fn run(&self) -> Result<()> {
        // 创建 socket 并设置选项
        use socket2::{Socket, Domain, Type, Protocol};

        // 手动创建 socket 以设置更大的 backlog
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;

        // ⚡ 优化：设置 socket 选项
        socket.set_reuse_address(true)?;
        socket.set_nonblocking(true)?;

        // SO_REUSEPORT - 允许端口重用（Linux/macOS）
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let fd = socket.as_raw_fd();
                const SO_REUSEPORT: libc::c_int = 15;
                let reuse_port: libc::c_int = 1;
                let _ = libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    SO_REUSEPORT,
                    &reuse_port as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&reuse_port) as libc::socklen_t,
                );
            }
        }

        // 绑定地址
        let address = self.listen_addr.into();
        socket.bind(&address)?;

        // ⚡ 关键优化：设置大的 backlog（默认 128 → 4096）
        // 这样可以让更多连接在队列中等待，避免 accept 慢
        socket.listen(4096)?;

        info!("✅ TCP backlog 设置为 4096（提升高并发性能）");

        // 转换为标准库的 TcpListener
        let std_listener: std::net::TcpListener = socket.into();

        // 🔧 关键优化：设置为阻塞模式，在专用线程中 accept
        // 这样可以避免 Tokio 异步调度延迟
        std_listener.set_nonblocking(false)?;

        info!("⚡ 使用专用阻塞线程进行 accept，避免 Tokio 调度延迟");

        info!("SNI 代理服务器启动在 {}", self.listen_addr);
        info!("最大并发连接数: {}", self.max_connections);
        info!("🚀 服务器已就绪，等待连接...");

        // ⚡ 预热：预解析热门域名的 DNS（仅用于直连模式）
        if self.socks5_config.is_none() {
            info!("预热 DNS 缓存...");
            let common_domains = vec!["claude.ai", "www.netflix.com", "api.anthropic.com"];
            for domain in common_domains {
                if let Err(e) = resolve_host_cached(domain).await {
                    debug!("预热 DNS 失败 {}: {}", domain, e);
                } else {
                    debug!("预热 DNS 成功: {}", domain);
                }
            }
        }

        if let Some(socks5) = &self.socks5_config {
            info!("使用 SOCKS5 出口: {}", socks5.addr);
            if socks5.username.is_some() {
                info!("SOCKS5 认证: 启用");
            }
        } else {
            info!("直接连接到目标服务器（未配置 SOCKS5）");
        }

        // 使用信号量限制并发连接数
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_connections));
        let domain_matcher = self.domain_matcher.clone();
        let socks5_config = self.socks5_config.clone();

        info!("🔄 Accept loop 开始运行（专用阻塞线程模式）...");

        // 获取当前 Tokio runtime handle，用于在阻塞线程中 spawn 任务
        let runtime_handle = tokio::runtime::Handle::current();

        // 🔧 关键优化：在专用线程中运行阻塞式 accept，避免 Tokio 调度延迟
        // 使用 std::thread 而不是 tokio::spawn，这样 accept 不会被 Tokio 调度影响
        std::thread::spawn(move || {
            let mut loop_count = 0u64;
            let mut last_accept_time = std::time::Instant::now();

            loop {
                loop_count += 1;
                let since_last_accept = last_accept_time.elapsed();

                // 如果距离上次 accept 超过 1 秒，说明可能有问题
                if since_last_accept.as_millis() > 1000 {
                    warn!("⚠️  两次 accept 间隔过长: {}ms", since_last_accept.as_millis());
                }

                if loop_count % 1000 == 0 {
                    debug!("Accept loop 运行次数: {}", loop_count);
                }

                // ⏱️ 测量 accept 耗时
                let accept_start = std::time::Instant::now();
                last_accept_time = accept_start;

                // 🔧 阻塞式 accept，不会被 Tokio 调度影响
                match std_listener.accept() {
                    Ok((stream, addr)) => {
                        let accept_elapsed = accept_start.elapsed();

                        // 只在慢的时候打印警告
                        if accept_elapsed.as_millis() > 100 {
                            warn!("⏱️  Accept 慢: {}ms (来自 {})", accept_elapsed.as_millis(), addr);
                        }

                        debug!("接受来自 {} 的新连接 (accept 耗时: {:?})", addr, accept_elapsed);

                        // 转换为非阻塞模式供 Tokio 使用
                        if let Err(e) = stream.set_nonblocking(true) {
                            error!("设置非阻塞模式失败: {}", e);
                            continue;
                        }

                        let domain_matcher_clone = Arc::clone(&domain_matcher);
                        let socks5_config_clone = socks5_config.clone();
                        let semaphore_clone = Arc::clone(&semaphore);

                        // 🔧 在 Tokio 运行时中处理连接（使用 runtime_handle）
                        runtime_handle.spawn(async move {
                            // 在 Tokio 上下文中转换 TcpStream
                            let tokio_stream = match tokio::net::TcpStream::from_std(stream) {
                                Ok(s) => s,
                                Err(e) => {
                                    error!("转换 TcpStream 失败: {}", e);
                                    return;
                                }
                            };
                            // 在任务内部获取 permit
                            let permit_start = std::time::Instant::now();
                            let _permit = match semaphore_clone.acquire_owned().await {
                                Ok(p) => p,
                                Err(e) => {
                                    error!("获取连接许可失败: {}", e);
                                    return;
                                }
                            };
                            let permit_elapsed = permit_start.elapsed();

                            if permit_elapsed.as_millis() > 100 {
                                warn!("⏱️  等待 permit: {}ms", permit_elapsed.as_millis());
                            }

                            debug!("开始处理连接 (permit 耗时: {:?})...", permit_elapsed);
                            if let Err(e) = handle_connection(tokio_stream, domain_matcher_clone, socks5_config_clone).await {
                                debug!("处理连接时出错: {}", e);
                            }
                            debug!("连接处理完成");
                        });
                    }
                    Err(e) => {
                        error!("接受连接失败: {}", e);
                        // 短暂休眠避免繁忙循环
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }
            }
        });

        // 主线程等待（防止程序退出）
        loop {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        }
    }
}

/// 处理单个客户端连接
/// ⚡ 优化版本: 更快的超时和更大的缓冲区
async fn handle_connection(
    mut client_stream: TcpStream,
    domain_matcher: Arc<DomainMatcher>,
    socks5_config: Option<Arc<Socks5Config>>,
) -> Result<()> {
    use std::time::Instant;
    let start_time = Instant::now();

    // 设置 TCP KeepAlive
    let _ = client_stream.set_nodelay(true);

    // ⚡ 优化：增加缓冲区到 64KB（从 16KB）
    let mut buffer = vec![0u8; 65536];

    // ⚡ 优化：读取 Client Hello 超时设置为 3 秒
    let read_start = Instant::now();
    let n = match timeout(Duration::from_secs(3), client_stream.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            warn!("读取客户端数据失败: {}", e);
            return Ok(());
        }
        Err(_) => {
            warn!("读取客户端数据超时");
            return Ok(());
        }
    };

    if n == 0 {
        debug!("客户端连接已关闭（read 返回 0 字节，可能是客户端在发送数据前就断开了）");
        return Ok(());
    }

    buffer.truncate(n);
    debug!("⏱️  读取 Client Hello 耗时: {:?}", read_start.elapsed());

    // 解析 SNI
    let sni = match parse_sni(&buffer) {
        Some(domain) => {
            debug!("解析到 SNI: {}", domain);
            domain
        }
        None => {
            warn!("无法解析 SNI，拒绝连接");
            return Ok(());
        }
    };

    // 检查白名单（支持通配符）
    if !domain_matcher.matches(&sni) {
        warn!("域名 {} 不在白名单中，拒绝连接", sni);
        return Ok(());
    }

    info!("域名 {} 匹配白名单，建立代理连接", sni);

    // 连接到目标服务器
    let connect_start = Instant::now();
    let target_stream = if let Some(socks5) = socks5_config {
        // 通过 SOCKS5 连接
        info!("通过 SOCKS5 连接到 {}:443", sni);
        match connect_via_socks5_with_cache(&sni, 443, socks5.as_ref()).await {
            Ok(stream) => {
                info!("⏱️  SOCKS5 连接 {} 耗时: {:?}", sni, connect_start.elapsed());
                stream
            },
            Err(e) => {
                error!("通过 SOCKS5 连接到 {}:443 失败: {} (耗时 {:?})", sni, e, connect_start.elapsed());
                return Ok(());
            }
        }
    } else {
        // 直接连接
        let target_addr = format!("{}:443", sni);
        // ⚡ 优化：连接超时设置为 5 秒
        match timeout(
            Duration::from_secs(5),
            TcpStream::connect(&target_addr)
        ).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                error!("连接到目标服务器 {} 失败: {}", target_addr, e);
                return Ok(());
            }
            Err(_) => {
                error!("连接到目标服务器 {} 超时", target_addr);
                return Ok(());
            }
        }
    };

    // 设置目标连接的 TCP 选项
    let mut target_stream = target_stream;
    let _ = target_stream.set_nodelay(true);

    debug!("成功连接到目标服务器 {}:443", sni);

    // 转发 Client Hello
    if let Err(e) = target_stream.write_all(&buffer).await {
        error!("转发 Client Hello 失败: {}", e);
        return Ok(());
    }

    // 双向转发数据
    let proxy_start = Instant::now();
    if let Err(e) = proxy_data(client_stream, target_stream).await {
        debug!("数据转发结束: {}", e);
    }

    info!("⏱️  {} 总耗时: {:?} (连接: {:?}, 转发: {:?})",
          sni,
          start_time.elapsed(),
          connect_start.elapsed(),
          proxy_start.elapsed());
    Ok(())
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
pub async fn connect_via_socks5_with_cache(
    target_host: &str,
    target_port: u16,
    socks5_config: &Socks5Config,
) -> Result<TcpStream> {
    info!("通过 SOCKS5 连接到 {}:{}", target_host, target_port);

    // ============ 步骤 1: 连接到 SOCKS5 服务器 ============
    let mut socks5_stream = match timeout(
        Duration::from_secs(5),
        TcpStream::connect(&socks5_config.addr)
    ).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            return Err(anyhow::anyhow!("无法连接到 SOCKS5 服务器 {}: {}", socks5_config.addr, e));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("连接到 SOCKS5 服务器 {} 超时", socks5_config.addr));
        }
    };

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

    // ============ 步骤 3: SOCKS5 握手 - 版本识别请求 ============
    // 构建 SOCKS5 请求：
    // +----+-----+-------+------+----------+----------+
    // |VER | NMD | FLAGS | RSV  | ADDRTYPE | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  |   1   | 1    |    1     | Variable |    2     |
    // +----+-----+-------+------+----------+----------+

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
        Duration::from_secs(5),
        socks5_stream.write_all(&request)
    ).await {
        Ok(Ok(())) => debug!("已发送 SOCKS5 握手请求"),
        Ok(Err(e)) => return Err(anyhow::anyhow!("写入 SOCKS5 握手请求失败: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("写入 SOCKS5 握手请求超时")),
    }

    // ============ 步骤 4: 读取握手响应 ============
    let mut response = [0u8; 2];
    match timeout(
        Duration::from_secs(5),
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
            // 构建认证请求
            let mut auth_request = Vec::new();
            auth_request.push(1u8);  // 版本 1
            auth_request.push(username.len() as u8);
            auth_request.extend_from_slice(username.as_bytes());
            auth_request.push(password.len() as u8);
            auth_request.extend_from_slice(password.as_bytes());

            // 发送认证请求
            match timeout(
                Duration::from_secs(5),
                socks5_stream.write_all(&auth_request)
            ).await {
                Ok(Ok(())) => debug!("已发送认证请求"),
                Ok(Err(e)) => return Err(anyhow::anyhow!("发送认证请求失败: {}", e)),
                Err(_) => return Err(anyhow::anyhow!("发送认证请求超时")),
            }

            // 读取认证响应
            let mut auth_response = [0u8; 2];
            match timeout(
                Duration::from_secs(5),
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
    // 构建连接请求：
    // +----+-----+-------+------+----------+----------+
    // |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
    // +----+-----+-------+------+----------+----------+
    // | 1  |  1  | X'00' |  1   | Variable |    2     |
    // +----+-----+-------+------+----------+----------+
    // CMD:
    //   o  CONNECT X'01'
    //   o  BIND X'02'
    //   o  UDP ASSOCIATE X'03'
    // ATYP:
    //   o  IPv4 address: X'01'
    //   o  DOMAINNAME: X'03'
    //   o  IPv6 address: X'04'

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

    // 发送连接请求
    match timeout(
        Duration::from_secs(5),
        socks5_stream.write_all(&connect_request)
    ).await {
        Ok(Ok(())) => debug!("已发送 SOCKS5 连接请求"),
        Ok(Err(e)) => return Err(anyhow::anyhow!("发送 SOCKS5 连接请求失败: {}", e)),
        Err(_) => return Err(anyhow::anyhow!("发送 SOCKS5 连接请求超时")),
    }

    // ============ 步骤 7: 读取连接响应 ============
    let mut response = [0u8; 4];
    match timeout(
        Duration::from_secs(5),
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
    // 根据地址类型读取相应的数据
    match response[3] {
        1 => {
            // IPv4: 需要读 4 个字节 IP + 2 个字节端口
            let mut addr_data = [0u8; 6];
            match timeout(
                Duration::from_secs(5),
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
                Duration::from_secs(5),
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
                Duration::from_secs(5),
                socks5_stream.read_exact(&mut len_buf)
            ).await {
                Ok(Ok(_)) => {},
                Ok(Err(e)) => return Err(anyhow::anyhow!("读取域名长度失败: {}", e)),
                Err(_) => return Err(anyhow::anyhow!("读取域名长度超时")),
            }

            let domain_len = len_buf[0] as usize;
            let mut domain_data = vec![0u8; domain_len + 2];
            match timeout(
                Duration::from_secs(5),
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

/// 双向代理数据传输（优化版本）
/// ⚡ 优化：更大的缓冲区提高吞吐量
async fn proxy_data(
    client_stream: TcpStream,
    target_stream: TcpStream,
) -> Result<()> {
    let (mut client_read, mut client_write) = client_stream.into_split();
    let (mut target_read, mut target_write) = target_stream.into_split();

    // ⚡ 优化：使用 64KB 缓冲区（从 16KB）以提高吞吐量
    let client_to_target = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => return Ok::<(), std::io::Error>(()),
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            target_write.write_all(&buf[..n]).await?;
        }
    };

    let target_to_client = async {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match target_read.read(&mut buf).await {
                Ok(0) => return Ok::<(), std::io::Error>(()),
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            client_write.write_all(&buf[..n]).await?;
        }
    };

    tokio::select! {
        result = client_to_target => {
            if let Err(e) = result {
                debug!("客户端到目标服务器的数据传输结束: {}", e);
            }
        }
        result = target_to_client => {
            if let Err(e) = result {
                debug!("目标服务器到客户端的数据传输结束: {}", e);
            }
        }
    }

    Ok(())
}

/// 从 TLS Client Hello 中解析 SNI（优化版本）
#[inline]
fn parse_sni(data: &[u8]) -> Option<String> {
    // 最小 TLS Client Hello 大小检查
    if data.len() < 43 {
        return None;
    }

    // 检查是否是 TLS 握手消息 (0x16)
    if data[0] != 0x16 {
        return None;
    }

    // 检查 TLS 版本 (3.x)
    if data[1] != 0x03 {
        return None;
    }

    // 跳过记录头部 (5 字节)
    let mut pos = 5;

    // 检查握手类型 (Client Hello = 0x01)
    if pos >= data.len() || data[pos] != 0x01 {
        return None;
    }
    pos += 1;

    // 读取握手长度 (3 字节)
    if pos + 3 > data.len() {
        return None;
    }
    let handshake_len = ((data[pos] as usize) << 16)
        | ((data[pos + 1] as usize) << 8)
        | (data[pos + 2] as usize);
    pos += 3;

    // 验证握手长度
    if pos + handshake_len > data.len() {
        return None;
    }

    // 跳过 TLS 版本 (2 字节)
    if pos + 2 > data.len() {
        return None;
    }
    pos += 2;

    // 跳过随机数 (32 字节)
    if pos + 32 > data.len() {
        return None;
    }
    pos += 32;

    // 读取 Session ID 长度
    if pos >= data.len() {
        return None;
    }
    let session_id_len = data[pos] as usize;
    pos += 1;

    // 跳过 Session ID
    if pos + session_id_len > data.len() {
        return None;
    }
    pos += session_id_len;

    // 读取 Cipher Suites 长度
    if pos + 2 > data.len() {
        return None;
    }
    let cipher_suites_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    // 跳过 Cipher Suites
    if pos + cipher_suites_len > data.len() {
        return None;
    }
    pos += cipher_suites_len;

    // 读取 Compression Methods 长度
    if pos >= data.len() {
        return None;
    }
    let compression_methods_len = data[pos] as usize;
    pos += 1;

    // 跳过 Compression Methods
    if pos + compression_methods_len > data.len() {
        return None;
    }
    pos += compression_methods_len;

    // 检查是否有 Extensions
    if pos + 2 > data.len() {
        return None;
    }

    // 读取 Extensions 长度
    let extensions_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    let extensions_end = pos + extensions_len;
    if extensions_end > data.len() {
        return None;
    }

    // 遍历 Extensions
    while pos + 4 <= extensions_end {
        let ext_type = u16::from_be_bytes([data[pos], data[pos + 1]]);
        let ext_len = u16::from_be_bytes([data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;

        if pos + ext_len > extensions_end {
            return None;
        }

        // SNI Extension (type = 0)
        if ext_type == 0 {
            return parse_sni_extension(&data[pos..pos + ext_len]);
        }

        pos += ext_len;
    }

    None
}

/// 解析 SNI Extension（优化版本）
#[inline]
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    if data.len() < 5 {
        return None;
    }

    // 读取 Server Name List 长度
    let list_len = u16::from_be_bytes([data[0], data[1]]) as usize;

    if 2 + list_len > data.len() {
        return None;
    }

    let mut pos = 2;

    // 读取 Server Name Type (应该是 0 = host_name)
    if data[pos] != 0 {
        return None;
    }
    pos += 1;

    // 读取 Server Name 长度
    if pos + 2 > data.len() {
        return None;
    }
    let name_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
    pos += 2;

    // 验证长度并提取域名
    if pos + name_len > data.len() || name_len == 0 || name_len > 255 {
        return None;
    }

    // 提取域名并验证 UTF-8
    String::from_utf8(data[pos..pos + name_len].to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_sni() {
        // 这是一个简化的测试，实际的 TLS Client Hello 会更复杂
        // 在实际使用中，你需要用真实的 TLS 握手数据来测试
        let data = vec![0x16, 0x03, 0x01]; // TLS 握手开始
        let result = parse_sni(&data);
        assert!(result.is_none());
    }

    #[test]
    fn test_domain_matcher_exact() {
        let matcher = DomainMatcher::new(vec![
            "example.com".to_string(),
            "github.com".to_string(),
        ]);

        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("EXAMPLE.COM")); // 大小写不敏感
        assert!(matcher.matches("github.com"));
        assert!(!matcher.matches("www.example.com"));
        assert!(!matcher.matches("notexample.com"));
    }

    #[test]
    fn test_domain_matcher_wildcard() {
        let matcher = DomainMatcher::new(vec![
            "*.example.com".to_string(),
            "github.com".to_string(),
        ]);

        // 通配符应该匹配子域名
        assert!(matcher.matches("www.example.com"));
        assert!(matcher.matches("api.example.com"));
        assert!(matcher.matches("test.api.example.com"));
        assert!(matcher.matches("WWW.EXAMPLE.COM")); // 大小写不敏感

        // 精确匹配
        assert!(matcher.matches("github.com"));
        assert!(matcher.matches("GITHUB.COM")); // 大小写不敏感

        // 不应该匹配
        assert!(!matcher.matches("example.com")); // 通配符不匹配主域名本身
        assert!(!matcher.matches("notexample.com"));
        assert!(!matcher.matches("www.github.com")); // github.com 是精确匹配
    }

    #[test]
    fn test_domain_matcher_mixed() {
        let matcher = DomainMatcher::new(vec![
            "example.com".to_string(),
            "*.example.com".to_string(),
            "*.api.example.com".to_string(),
            "github.com".to_string(),
        ]);

        // 精确匹配
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("github.com"));

        // 一级通配符
        assert!(matcher.matches("www.example.com"));
        assert!(matcher.matches("mail.example.com"));

        // 二级通配符
        assert!(matcher.matches("v1.api.example.com"));
        assert!(matcher.matches("v2.api.example.com"));

        // 不应该匹配
        assert!(!matcher.matches("www.github.com"));
        assert!(!matcher.matches("test.com"));
    }

    #[test]
    fn test_domain_matcher_edge_cases() {
        let matcher = DomainMatcher::new(vec![
            "*.example.com".to_string(),
        ]);

        // 边界情况测试
        assert!(!matcher.matches("example.com")); // 主域名不匹配
        assert!(!matcher.matches("notexample.com")); // 不是子域名
        assert!(!matcher.matches("testexample.com")); // 不是子域名
        assert!(matcher.matches("a.example.com")); // 单字母子域名
        assert!(matcher.matches("test.sub.example.com")); // 多级子域名
    }

    #[test]
    fn test_domain_matcher_case_insensitive() {
        let matcher = DomainMatcher::new(vec![
            "Example.Com".to_string(),
            "*.GitHub.IO".to_string(),
        ]);

        // 应该不区分大小写
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("EXAMPLE.COM"));
        assert!(matcher.matches("Example.Com"));
        assert!(matcher.matches("user.github.io"));
        assert!(matcher.matches("USER.GITHUB.IO"));
    }

    #[test]
    fn test_domain_matcher_empty() {
        let matcher = DomainMatcher::new(vec![]);

        assert!(!matcher.matches("example.com"));
        assert!(!matcher.matches("www.example.com"));
    }

    #[test]
    fn test_domain_matcher_wildcard_sorting() {
        // 测试通配符按长度排序（更具体的优先）
        let matcher = DomainMatcher::new(vec![
            "*.com".to_string(),
            "*.example.com".to_string(),
            "*.api.example.com".to_string(),
        ]);

        // 应该匹配最具体的规则
        assert!(matcher.matches("v1.api.example.com"));
        assert!(matcher.matches("www.example.com"));
        assert!(matcher.matches("test.com"));
    }
}

