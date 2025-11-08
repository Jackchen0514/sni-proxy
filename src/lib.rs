use anyhow::{Context, Result};
use log::{debug, error, info, warn};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

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
}

impl SniProxy {
    /// 创建新的 SNI 代理实例
    pub fn new(listen_addr: SocketAddr, whitelist: Vec<String>) -> Self {
        let domain_matcher = DomainMatcher::new(whitelist);

        Self {
            listen_addr,
            domain_matcher: Arc::new(domain_matcher),
            max_connections: 10000, // 默认最大并发连接数
        }
    }

    /// 设置最大并发连接数
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// 启动代理服务器
    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(self.listen_addr)
            .await
            .context("绑定监听地址失败")?;

        info!("SNI 代理服务器启动在 {}", self.listen_addr);
        info!("最大并发连接数: {}", self.max_connections);

        // 使用信号量限制并发连接数
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_connections));

        loop {
            // 获取连接许可
            let permit = semaphore.clone().acquire_owned().await?;

            match listener.accept().await {
                Ok((client_stream, client_addr)) => {
                    debug!("接受来自 {} 的新连接", client_addr);
                    let domain_matcher = Arc::clone(&self.domain_matcher);

                    tokio::spawn(async move {
                        // 持有许可直到连接处理完成
                        let _permit = permit;

                        if let Err(e) = handle_connection(client_stream, domain_matcher).await {
                            debug!("处理连接时出错: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("接受连接失败: {}", e);
                    // 短暂休眠避免繁忙循环
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
}

/// 处理单个客户端连接
async fn handle_connection(
    mut client_stream: TcpStream,
    domain_matcher: Arc<DomainMatcher>,
) -> Result<()> {
    // 设置 TCP KeepAlive
    let _ = client_stream.set_nodelay(true);

    // 读取 TLS Client Hello（带超时）
    let mut buffer = vec![0u8; 8192]; // 增加缓冲区大小

    let n = match timeout(Duration::from_secs(10), client_stream.read(&mut buffer)).await {
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
        debug!("客户端连接已关闭");
        return Ok(());
    }

    buffer.truncate(n);

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

    // 连接到目标服务器（带超时和重试）
    let target_addr = format!("{}:443", sni);
    let mut target_stream = match timeout(
        Duration::from_secs(10),
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
    };

    // 设置目标连接的 TCP 选项
    let _ = target_stream.set_nodelay(true);

    debug!("成功连接到目标服务器 {}", target_addr);

    // 转发 Client Hello
    if let Err(e) = target_stream.write_all(&buffer).await {
        error!("转发 Client Hello 失败: {}", e);
        return Ok(());
    }

    // 双向转发数据
    if let Err(e) = proxy_data(client_stream, target_stream).await {
        debug!("数据转发结束: {}", e);
    }

    debug!("连接关闭: {}", sni);
    Ok(())
}

/// 双向代理数据传输（优化版本）
async fn proxy_data(
    client_stream: TcpStream,
    target_stream: TcpStream,
) -> Result<()> {
    let (mut client_read, mut client_write) = client_stream.into_split();
    let (mut target_read, mut target_write) = target_stream.into_split();

    // 使用更大的缓冲区提高性能
    let client_to_target = async {
        let mut buf = vec![0u8; 16384];
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
        let mut buf = vec![0u8; 16384];
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