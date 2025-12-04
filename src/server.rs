use anyhow::Result;
use futures::FutureExt;
use log::{debug, error, info, warn};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use tokio::sync::watch;

use crate::dns::resolve_host_cached;
use crate::domain::DomainMatcher;
use crate::domain_ip_tracker::DomainIpTracker;
use crate::ip_matcher::IpMatcher;
use crate::ip_traffic::IpTrafficTracker;
use crate::metrics::{ConnectionGuard, Metrics};
use crate::proxy::proxy_data;
use crate::socks5::{connect_via_socks5, Socks5Config};
use crate::tls::parse_sni;

/// SNI 代理服务器
pub struct SniProxy {
    /// 监听地址
    listen_addr: SocketAddr,
    /// 直连白名单域名匹配器
    direct_matcher: Arc<DomainMatcher>,
    /// SOCKS5 白名单域名匹配器
    socks5_matcher: Option<Arc<DomainMatcher>>,
    /// IP 白名单匹配器（可选）
    ip_matcher: Option<Arc<IpMatcher>>,
    /// 最大并发连接数
    max_connections: usize,
    /// SOCKS5 代理配置（可选）
    socks5_config: Option<Arc<Socks5Config>>,
    /// 性能监控指标
    metrics: Metrics,
    /// IP 流量追踪器
    ip_traffic_tracker: IpTrafficTracker,
    /// 域名-IP 追踪器
    domain_ip_tracker: DomainIpTracker,
}

impl SniProxy {
    /// 创建新的 SNI 代理实例（仅直连白名单）
    pub fn new(listen_addr: SocketAddr, direct_whitelist: Vec<String>) -> Self {
        let direct_matcher = DomainMatcher::new(direct_whitelist);

        // 🚀 自适应最大连接数：根据 CPU 核心数动态调整
        // 经验值：每核心支持 500-1000 个并发连接
        let num_cpus = num_cpus::get();
        let max_connections = if num_cpus <= 2 {
            // 小型服务器（1-2核）：500-1000 连接
            num_cpus * 500
        } else if num_cpus <= 8 {
            // 中型服务器（4-8核）：2000-4000 连接
            num_cpus * 500
        } else {
            // 大型服务器（16+核）：8000-10000 连接
            std::cmp::min(10000, num_cpus * 500)
        };

        Self {
            listen_addr,
            direct_matcher: Arc::new(direct_matcher),
            socks5_matcher: None,
            ip_matcher: None,
            max_connections, // 自适应最大并发连接数
            socks5_config: None,
            metrics: Metrics::new(),
            ip_traffic_tracker: IpTrafficTracker::disabled(), // 默认禁用
            domain_ip_tracker: DomainIpTracker::disabled(), // 默认禁用
        }
    }

    /// 创建新的 SNI 代理实例（同时支持直连和 SOCKS5 白名单）
    pub fn new_with_dual_whitelist(
        listen_addr: SocketAddr,
        direct_whitelist: Vec<String>,
        socks5_whitelist: Vec<String>,
    ) -> Self {
        let direct_matcher = DomainMatcher::new(direct_whitelist);
        let socks5_matcher = if socks5_whitelist.is_empty() {
            None
        } else {
            Some(Arc::new(DomainMatcher::new(socks5_whitelist)))
        };

        // 🚀 自适应最大连接数：根据 CPU 核心数动态调整
        let num_cpus = num_cpus::get();
        let max_connections = if num_cpus <= 2 {
            num_cpus * 500
        } else if num_cpus <= 8 {
            num_cpus * 500
        } else {
            std::cmp::min(10000, num_cpus * 500)
        };

        Self {
            listen_addr,
            direct_matcher: Arc::new(direct_matcher),
            socks5_matcher,
            ip_matcher: None,
            max_connections, // 自适应最大并发连接数
            socks5_config: None,
            metrics: Metrics::new(),
            ip_traffic_tracker: IpTrafficTracker::disabled(), // 默认禁用
            domain_ip_tracker: DomainIpTracker::disabled(), // 默认禁用
        }
    }

    /// 设置 IP 白名单
    pub fn with_ip_whitelist(mut self, ip_whitelist: Vec<String>) -> Self {
        let ip_matcher = IpMatcher::new(ip_whitelist);
        // 只有在 IP 白名单不为空时才设置
        if !ip_matcher.is_empty() {
            self.ip_matcher = Some(Arc::new(ip_matcher));
        }
        self
    }

    /// 设置最大并发连接数
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_connections = max_connections;
        self
    }

    /// 设置 SOCKS5 代理配置
    pub fn with_socks5(mut self, socks5_config: Socks5Config) -> Self {
        self.socks5_config = Some(Arc::new(socks5_config));
        self
    }

    /// 启用 IP 流量追踪（仅对 IP 白名单中的 IP 进行统计）
    ///
    /// # 参数
    /// * `max_tracked_ips` - 最大跟踪的 IP 数量（使用 LRU 缓存）
    /// * `output_file` - 统计数据输出文件路径（可选）
    /// * `persistence_file` - 持久化数据文件路径（可选）
    pub fn with_ip_traffic_tracking(
        mut self,
        max_tracked_ips: usize,
        output_file: Option<String>,
        persistence_file: Option<String>,
    ) -> Self {
        self.ip_traffic_tracker = IpTrafficTracker::new(max_tracked_ips, output_file, persistence_file);
        self
    }

    /// 启用域名-IP 追踪（记录所有通过的域名及其解析的 IP）
    ///
    /// # 参数
    /// * `output_file` - 输出文件路径（可选）
    pub fn with_domain_ip_tracking(mut self, output_file: Option<String>) -> Self {
        self.domain_ip_tracker = DomainIpTracker::new(output_file);
        self
    }

    /// 获取监控指标
    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// 启动代理服务器
    ///
    /// # 参数
    /// * `shutdown_rx` - 可选的关闭信号接收器，用于优雅关闭
    pub async fn run(&self) -> Result<()> {
        self.run_with_shutdown(None).await
    }

    /// 启动代理服务器（支持优雅关闭）
    ///
    /// # 参数
    /// * `shutdown_rx` - 可选的关闭信号接收器
    pub async fn run_with_shutdown(&self, mut shutdown_rx: Option<watch::Receiver<bool>>) -> Result<()> {
        // 创建 socket 并设置选项
        use socket2::{Domain, Protocol, Socket, Type};

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

        // ⚡ TCP Fast Open (服务端模式) - Linux 3.7+ 支持
        // 允许客户端在 SYN 包中携带数据，节省 1 RTT
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            unsafe {
                let fd = socket.as_raw_fd();
                const TCP_FASTOPEN: libc::c_int = 23; // Linux TCP_FASTOPEN 常量
                let queue_len: libc::c_int = 256; // TFO 队列长度
                let result = libc::setsockopt(
                    fd,
                    libc::IPPROTO_TCP,
                    TCP_FASTOPEN,
                    &queue_len as *const _ as *const libc::c_void,
                    std::mem::size_of_val(&queue_len) as libc::socklen_t,
                );

                if result == 0 {
                    info!("✅ TCP Fast Open 已启用（服务端模式，队列: {}）", queue_len);
                } else {
                    warn!("⚠️  TCP Fast Open 启用失败（系统可能不支持）");
                    warn!("   提示: 检查 /proc/sys/net/ipv4/tcp_fastopen");
                }
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

        // 转换为 Tokio 的 TcpListener
        let listener = TcpListener::from_std(std_listener)?;

        info!("SNI 代理服务器启动在 {}", self.listen_addr);
        info!("最大并发连接数: {}", self.max_connections);

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

        // 启动后台任务：每分钟打印监控指标
        let metrics_clone = self.metrics.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                metrics_clone.print_summary();
            }
        });

        // 启动后台任务：每分钟打印 IP 流量统计（仅在启用时）
        if self.ip_traffic_tracker.is_enabled() {
            let ip_traffic_tracker_clone = self.ip_traffic_tracker.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    ip_traffic_tracker_clone.print_summary(10); // 打印 TOP 10
                }
            });
            info!("✅ IP 流量追踪已启用");

            // 启动后台任务：每 5 分钟保存一次持久化数据
            let ip_traffic_tracker_clone = self.ip_traffic_tracker.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 分钟
                loop {
                    interval.tick().await;
                    info!("💾 定期保存 IP 流量统计数据...");
                    ip_traffic_tracker_clone.save_to_persistence_file();
                }
            });
            info!("✅ IP 流量追踪定期保存已启用（每 5 分钟）");
        }

        // 启动后台任务：每分钟打印域名-IP 统计（仅在启用时）
        if self.domain_ip_tracker.is_enabled() {
            let domain_ip_tracker_clone = self.domain_ip_tracker.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    domain_ip_tracker_clone.print_summary();
                }
            });
            info!("✅ 域名-IP 追踪已启用");

            // 启动后台任务：每 5 分钟保存一次域名-IP 映射
            let domain_ip_tracker_clone = self.domain_ip_tracker.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(300)); // 5 分钟
                loop {
                    interval.tick().await;
                    info!("💾 定期保存域名-IP 映射数据...");
                    if let Err(e) = domain_ip_tracker_clone.save_to_file() {
                        error!("保存域名-IP 映射失败: {}", e);
                    }
                }
            });
            info!("✅ 域名-IP 追踪定期保存已启用（每 5 分钟）");
        }

        loop {
            use std::time::Instant;

            // 如果提供了关闭信号，使用 select! 监听关闭和新连接
            let should_shutdown = if let Some(ref mut rx) = shutdown_rx {
                tokio::select! {
                    // 监听关闭信号
                    _ = rx.changed() => {
                        if *rx.borrow() {
                            info!("🛑 收到关闭信号，停止接受新连接");
                            // 等待活跃连接完成（最多 30 秒）
                            info!("⏳ 等待活跃连接完成...");
                            let wait_start = Instant::now();

                            // 使用循环检查活跃连接数
                            for _ in 0..30 {
                                let active = self.metrics.get_active_connections();
                                if active == 0 {
                                    info!("✅ 所有连接已关闭");
                                    break;
                                }
                                info!("⏳ 等待 {} 个活跃连接关闭...", active);
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }

                            let final_active = self.metrics.get_active_connections();
                            if final_active > 0 {
                                warn!("⚠️  超时：仍有 {} 个连接未关闭，强制退出", final_active);
                            }

                            info!("⏱️  关闭耗时: {:?}", wait_start.elapsed());

                            // 保存 IP 流量统计数据
                            if self.ip_traffic_tracker.is_enabled() {
                                info!("💾 保存 IP 流量统计数据...");
                                self.ip_traffic_tracker.save_to_persistence_file();
                            }

                            // 保存域名-IP 映射数据
                            if self.domain_ip_tracker.is_enabled() {
                                info!("💾 保存域名-IP 映射数据...");
                                if let Err(e) = self.domain_ip_tracker.save_to_file() {
                                    error!("保存域名-IP 映射失败: {}", e);
                                }
                            }

                            // 打印最终统计
                            info!("📊 最终统计:");
                            self.metrics.print_summary();

                            return Ok(());
                        }
                        false
                    }
                    // 监听新连接
                    accept_result = listener.accept() => {
                        match accept_result {
                            Ok((client_stream, client_addr)) => {
                                handle_new_connection(
                                    client_stream,
                                    client_addr,
                                    &semaphore,
                                    &self,
                                    Instant::now(),
                                ).await;
                                false
                            }
                            Err(e) => {
                                error!("接受连接失败: {}", e);
                                tokio::time::sleep(Duration::from_millis(100)).await;
                                false
                            }
                        }
                    }
                }
            } else {
                // 没有关闭信号，直接 accept
                match listener.accept().await {
                    Ok((client_stream, client_addr)) => {
                        handle_new_connection(
                            client_stream,
                            client_addr,
                            &semaphore,
                            &self,
                            Instant::now(),
                        ).await;
                        false
                    }
                    Err(e) => {
                        error!("接受连接失败: {}", e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        false
                    }
                }
            };

            if should_shutdown {
                break;
            }
        }

        Ok(())
    }
}

/// 处理新连接的辅助函数
async fn handle_new_connection(
    client_stream: TcpStream,
    client_addr: SocketAddr,
    semaphore: &Arc<tokio::sync::Semaphore>,
    proxy: &SniProxy,
    accept_start: std::time::Instant,
) {
    let accept_elapsed = accept_start.elapsed();

    // ⏱️ 测量获取 permit 耗时
    let permit_start = std::time::Instant::now();
    let permit = match semaphore.clone().acquire_owned().await {
        Ok(p) => p,
        Err(e) => {
            error!("获取连接许可失败: {}", e);
            return;
        }
    };
    let permit_elapsed = permit_start.elapsed();

    // 只在慢的时候打印警告
    if accept_elapsed.as_millis() > 100 {
        warn!("⏱️  接受连接慢: {}ms (来自 {})", accept_elapsed.as_millis(), client_addr);
    }
    if permit_elapsed.as_millis() > 10 {
        debug!("⏱️  等待许可: {}ms", permit_elapsed.as_millis());
    }

    debug!("接受来自 {} 的新连接 (accept: {:?}, permit: {:?})",
           client_addr, accept_elapsed, permit_elapsed);

    let direct_matcher = Arc::clone(&proxy.direct_matcher);
    let socks5_matcher = proxy.socks5_matcher.clone();
    let ip_matcher = proxy.ip_matcher.clone();
    let socks5_config = proxy.socks5_config.clone();
    let metrics = proxy.metrics.clone();
    let ip_traffic_tracker = proxy.ip_traffic_tracker.clone();
    let domain_ip_tracker = proxy.domain_ip_tracker.clone();

    // 使用 catch_unwind 捕获 panic
    tokio::spawn(async move {
        // 持有许可直到连接处理完成
        let _permit = permit;

        // 捕获 panic 以防止任务崩溃
        let result = std::panic::AssertUnwindSafe(handle_connection(
            client_stream,
            client_addr,
            direct_matcher,
            socks5_matcher,
            ip_matcher,
            socks5_config,
            metrics.clone(),
            ip_traffic_tracker,
            domain_ip_tracker,
        ))
        .catch_unwind()
        .await;

        match result {
            Ok(Ok(())) => {
                // 连接正常完成
            }
            Ok(Err(e)) => {
                debug!("处理连接时出错: {}", e);
            }
            Err(panic_err) => {
                error!("❌ 连接处理任务 panic: {:?}", panic_err);
                metrics.inc_failed_connections();
            }
        }
    });
}

/// 处理单个客户端连接
/// ⚡ 优化版本: 更快的超时和更大的缓冲区
/// 支持分流: 直连白名单和 SOCKS5 白名单
/// 支持 IP 白名单: 只有在白名单中的 IP 才允许连接
async fn handle_connection(
    mut client_stream: TcpStream,
    client_addr: SocketAddr,
    direct_matcher: Arc<DomainMatcher>,
    socks5_matcher: Option<Arc<DomainMatcher>>,
    ip_matcher: Option<Arc<IpMatcher>>,
    socks5_config: Option<Arc<Socks5Config>>,
    metrics: Metrics,
    ip_traffic_tracker: IpTrafficTracker,
    domain_ip_tracker: DomainIpTracker,
) -> Result<()> {
    use std::time::Instant;
    let start_time = Instant::now();

    // 使用 ConnectionGuard 自动管理连接计数
    let _guard = ConnectionGuard::new(metrics.clone());

    let client_ip = client_addr.ip();

    // 检查 IP 白名单（如果配置了）
    let ip_in_whitelist = if let Some(ref ip_matcher) = ip_matcher {
        if !ip_matcher.matches(client_ip) {
            let rejected = metrics.get_rejected_requests() + 1;
            warn!("❌ IP {} 不在白名单中，拒绝连接 | 累计拒绝: {}", client_ip, rejected);
            metrics.inc_rejected_requests();
            return Ok(());
        }
        debug!("✅ IP {} 通过白名单检查 (来自 {})", client_ip, client_addr);
        true
    } else {
        false
    };

    // 如果 IP 在白名单中，记录连接（用于流量统计）
    if ip_in_whitelist {
        ip_traffic_tracker.record_connection(client_ip);
    }

    // ⚡ 流媒体优化：设置 TCP 参数（1MB 缓冲区 + TCP_NODELAY）
    let _ = crate::proxy::optimize_tcp_for_streaming(&client_stream);

    // ⚡ 自适应缓冲区大小：根据系统资源调整
    // TLS Client Hello 通常 < 4KB，但保留余量
    // 小型服务器（1-2核）：16KB（节省内存）
    // 中型服务器（4-8核）：32KB（平衡）
    // 大型服务器（16+核）：64KB（高性能）
    let num_cpus = num_cpus::get();
    let buffer_size = if num_cpus <= 2 {
        16384  // 16KB
    } else if num_cpus <= 8 {
        32768  // 32KB
    } else {
        65536  // 64KB
    };
    let mut buffer = vec![0u8; buffer_size];

    // ⚡ 自适应超时配置：根据服务器规模调整
    // 小型服务器：更短超时，快速失败，节省资源
    // 大型服务器：更长超时，容忍网络抖动
    let read_timeout_secs = if num_cpus <= 2 {
        2  // 小型服务器：2秒
    } else if num_cpus <= 8 {
        3  // 中型服务器：3秒
    } else {
        5  // 大型服务器：5秒
    };

    // ⚡ 优化：读取 Client Hello 超时自适应
    let read_start = Instant::now();
    let n = match timeout(Duration::from_secs(read_timeout_secs), client_stream.read(&mut buffer)).await {
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            warn!("读取客户端数据失败: {}", e);
            metrics.inc_failed_connections();
            return Ok(());
        }
        Err(_) => {
            warn!("读取客户端数据超时");
            metrics.inc_connection_timeouts();
            metrics.inc_failed_connections();
            return Ok(());
        }
    };

    if n == 0 {
        debug!("客户端连接已关闭");
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
            metrics.inc_sni_parse_errors();
            metrics.inc_failed_connections();
            return Ok(());
        }
    };

    // 检查白名单并决定连接方式
    // ⚡ 延迟优化：减少热路径日志，只在 debug 模式或失败时输出
    let use_socks5 = if let Some(ref socks5_matcher) = socks5_matcher {
        // 优先检查 SOCKS5 白名单
        if socks5_matcher.matches(&sni) {
            debug!("域名 {} 匹配 SOCKS5 白名单", sni);
            metrics.inc_socks5_requests();
            true
        } else if direct_matcher.matches(&sni) {
            debug!("域名 {} 匹配直连白名单", sni);
            metrics.inc_direct_requests();
            false
        } else {
            let rejected = metrics.get_rejected_requests() + 1;
            warn!("❌ 域名 {} 不在任何白名单中，拒绝连接 | 累计拒绝: {}", sni, rejected);
            metrics.inc_rejected_requests();
            return Ok(());
        }
    } else {
        // 如果没有 SOCKS5 白名单，只检查直连白名单
        if direct_matcher.matches(&sni) {
            debug!("域名 {} 匹配白名单，使用直连", sni);
            metrics.inc_direct_requests();
            false
        } else {
            let rejected = metrics.get_rejected_requests() + 1;
            warn!("❌ 域名 {} 不在白名单中，拒绝连接 | 累计拒绝: {}", sni, rejected);
            metrics.inc_rejected_requests();
            return Ok(());
        }
    };

    // 连接到目标服务器
    let connect_start = Instant::now();
    let target_stream = if use_socks5 && socks5_config.is_some() {
        // 通过 SOCKS5 连接
        let socks5 = socks5_config.as_ref().unwrap();
        debug!("通过 SOCKS5 连接到 {}:443", sni);
        match connect_via_socks5(&sni, 443, socks5.as_ref()).await {
            Ok(stream) => {
                debug!("⏱️  SOCKS5 连接 {} 耗时: {:?}", sni, connect_start.elapsed());
                stream
            },
            Err(e) => {
                error!("通过 SOCKS5 连接到 {}:443 失败: {} (耗时 {:?})", sni, e, connect_start.elapsed());
                metrics.inc_socks5_errors();
                metrics.inc_failed_connections();
                return Ok(());
            }
        }
    } else {
        // 直接连接
        // ⚡ 先解析 DNS，获取 IP 地址，用于域名-IP 追踪
        let resolved_ips = match resolve_host_cached(&sni).await {
            Ok(ips) => {
                // 记录域名和所有解析出的 IP
                for ip in &ips {
                    domain_ip_tracker.record(&sni, *ip);
                }
                ips
            },
            Err(e) => {
                error!("DNS 解析失败 {}: {}", sni, e);
                metrics.inc_failed_connections();
                return Ok(());
            }
        };

        // ⚡ 自适应连接超时：根据服务器规模调整
        let connect_timeout_secs = if num_cpus <= 2 {
            3  // 小型服务器：3秒（快速失败）
        } else if num_cpus <= 8 {
            5  // 中型服务器：5秒
        } else {
            8  // 大型服务器：8秒（容忍慢网络）
        };

        // 尝试连接到第一个 IP
        let target_addr = (resolved_ips[0], 443);
        match timeout(
            Duration::from_secs(connect_timeout_secs),
            TcpStream::connect(target_addr)
        ).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(e)) => {
                error!("连接到目标服务器 {}:{} 失败: {}", resolved_ips[0], 443, e);
                metrics.inc_failed_connections();
                return Ok(());
            }
            Err(_) => {
                error!("连接到目标服务器 {}:{} 超时", resolved_ips[0], 443);
                metrics.inc_connection_timeouts();
                metrics.inc_failed_connections();
                return Ok(());
            }
        }
    };

    // ⚡ 流媒体优化：设置目标连接的 TCP 参数
    let mut target_stream = target_stream;
    let _ = crate::proxy::optimize_tcp_for_streaming(&target_stream);

    // ⚡ 延迟优化：只在 debug 模式记录成功连接
    debug!("✅ 连接到 {}:443 成功 (耗时: {:?})", sni, connect_start.elapsed());

    // 转发 Client Hello
    if let Err(e) = target_stream.write_all(&buffer).await {
        error!("转发 Client Hello 失败: {}", e);
        return Ok(());
    }

    // 双向转发数据
    let proxy_start = Instant::now();
    if let Err(e) = proxy_data(
        client_stream,
        target_stream,
        metrics.clone(),
        client_ip,
        ip_traffic_tracker.clone(),
    )
    .await
    {
        debug!("数据转发结束: {}", e);
    }

    // ⚡ 延迟优化：性能统计只在 debug 模式输出
    debug!("⏱️  {} 总耗时: {:?} (连接: {:?}, 转发: {:?})",
          sni,
          start_time.elapsed(),
          connect_start.elapsed(),
          proxy_start.elapsed());
    Ok(())
}
