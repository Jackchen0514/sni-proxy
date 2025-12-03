use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 服务器性能监控指标
#[derive(Debug, Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

#[derive(Debug)]
struct MetricsInner {
    // 连接统计
    total_connections: AtomicU64,
    active_connections: AtomicUsize,
    failed_connections: AtomicU64,

    // 流量统计
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,

    // 请求统计
    direct_requests: AtomicU64,
    socks5_requests: AtomicU64,
    rejected_requests: AtomicU64,

    // DNS 统计
    dns_cache_hits: AtomicU64,
    dns_cache_misses: AtomicU64,

    // 错误统计
    sni_parse_errors: AtomicU64,
    socks5_errors: AtomicU64,
    connection_timeouts: AtomicU64,

    // 启动时间
    start_time: Instant,
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Metrics {
    /// 创建新的监控指标实例
    pub fn new() -> Self {
        Self {
            inner: Arc::new(MetricsInner {
                total_connections: AtomicU64::new(0),
                active_connections: AtomicUsize::new(0),
                failed_connections: AtomicU64::new(0),
                bytes_received: AtomicU64::new(0),
                bytes_sent: AtomicU64::new(0),
                direct_requests: AtomicU64::new(0),
                socks5_requests: AtomicU64::new(0),
                rejected_requests: AtomicU64::new(0),
                dns_cache_hits: AtomicU64::new(0),
                dns_cache_misses: AtomicU64::new(0),
                sni_parse_errors: AtomicU64::new(0),
                socks5_errors: AtomicU64::new(0),
                connection_timeouts: AtomicU64::new(0),
                start_time: Instant::now(),
            }),
        }
    }

    // 连接统计
    pub fn inc_total_connections(&self) {
        self.inner.total_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_active_connections(&self) {
        self.inner.active_connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn dec_active_connections(&self) {
        self.inner.active_connections.fetch_sub(1, Ordering::Relaxed);
    }

    pub fn inc_failed_connections(&self) {
        self.inner.failed_connections.fetch_add(1, Ordering::Relaxed);
    }

    // 流量统计
    pub fn add_bytes_received(&self, bytes: u64) {
        self.inner.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_bytes_sent(&self, bytes: u64) {
        self.inner.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    // 请求统计
    pub fn inc_direct_requests(&self) {
        self.inner.direct_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_socks5_requests(&self) {
        self.inner.socks5_requests.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_rejected_requests(&self) {
        self.inner.rejected_requests.fetch_add(1, Ordering::Relaxed);
    }

    // DNS 统计
    pub fn inc_dns_cache_hits(&self) {
        self.inner.dns_cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_dns_cache_misses(&self) {
        self.inner.dns_cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    // 错误统计
    pub fn inc_sni_parse_errors(&self) {
        self.inner.sni_parse_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_socks5_errors(&self) {
        self.inner.socks5_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn inc_connection_timeouts(&self) {
        self.inner.connection_timeouts.fetch_add(1, Ordering::Relaxed);
    }

    // 获取当前计数器值
    pub fn get_total_connections(&self) -> u64 {
        self.inner.total_connections.load(Ordering::Relaxed)
    }

    pub fn get_active_connections(&self) -> usize {
        self.inner.active_connections.load(Ordering::Relaxed)
    }

    pub fn get_rejected_requests(&self) -> u64 {
        self.inner.rejected_requests.load(Ordering::Relaxed)
    }

    // 获取指标快照
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total_connections: self.inner.total_connections.load(Ordering::Relaxed),
            active_connections: self.inner.active_connections.load(Ordering::Relaxed),
            failed_connections: self.inner.failed_connections.load(Ordering::Relaxed),
            bytes_received: self.inner.bytes_received.load(Ordering::Relaxed),
            bytes_sent: self.inner.bytes_sent.load(Ordering::Relaxed),
            direct_requests: self.inner.direct_requests.load(Ordering::Relaxed),
            socks5_requests: self.inner.socks5_requests.load(Ordering::Relaxed),
            rejected_requests: self.inner.rejected_requests.load(Ordering::Relaxed),
            dns_cache_hits: self.inner.dns_cache_hits.load(Ordering::Relaxed),
            dns_cache_misses: self.inner.dns_cache_misses.load(Ordering::Relaxed),
            sni_parse_errors: self.inner.sni_parse_errors.load(Ordering::Relaxed),
            socks5_errors: self.inner.socks5_errors.load(Ordering::Relaxed),
            connection_timeouts: self.inner.connection_timeouts.load(Ordering::Relaxed),
            uptime: self.inner.start_time.elapsed(),
        }
    }

    /// 打印监控指标
    pub fn print_summary(&self) {
        let snapshot = self.snapshot();
        log::info!("=== 性能监控指标 ===");
        log::info!("运行时间: {:?}", snapshot.uptime);
        log::info!("总连接数: {}", snapshot.total_connections);
        log::info!("活跃连接: {}", snapshot.active_connections);
        log::info!("失败连接: {}", snapshot.failed_connections);
        log::info!("直连请求: {}", snapshot.direct_requests);
        log::info!("SOCKS5 请求: {}", snapshot.socks5_requests);
        log::info!("拒绝请求: {}", snapshot.rejected_requests);
        log::info!("接收流量: {} MB", snapshot.bytes_received / 1024 / 1024);
        log::info!("发送流量: {} MB", snapshot.bytes_sent / 1024 / 1024);
        log::info!("DNS 缓存命中: {}", snapshot.dns_cache_hits);
        log::info!("DNS 缓存未命中: {}", snapshot.dns_cache_misses);

        if snapshot.dns_cache_hits + snapshot.dns_cache_misses > 0 {
            let hit_rate = (snapshot.dns_cache_hits as f64 /
                           (snapshot.dns_cache_hits + snapshot.dns_cache_misses) as f64) * 100.0;
            log::info!("DNS 缓存命中率: {:.2}%", hit_rate);
        }

        log::info!("SNI 解析错误: {}", snapshot.sni_parse_errors);
        log::info!("SOCKS5 错误: {}", snapshot.socks5_errors);
        log::info!("连接超时: {}", snapshot.connection_timeouts);
    }
}

/// 监控指标快照
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub total_connections: u64,
    pub active_connections: usize,
    pub failed_connections: u64,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub direct_requests: u64,
    pub socks5_requests: u64,
    pub rejected_requests: u64,
    pub dns_cache_hits: u64,
    pub dns_cache_misses: u64,
    pub sni_parse_errors: u64,
    pub socks5_errors: u64,
    pub connection_timeouts: u64,
    pub uptime: Duration,
}

/// RAII 风格的连接计数器
pub struct ConnectionGuard {
    metrics: Metrics,
}

impl ConnectionGuard {
    pub fn new(metrics: Metrics) -> Self {
        metrics.inc_total_connections();
        metrics.inc_active_connections();

        // Debug: 打印连接数统计
        let total = metrics.get_total_connections();
        let active = metrics.get_active_connections();
        log::debug!("📊 新连接建立 | 总连接数: {} | 活跃连接: {}", total, active);

        Self { metrics }
    }
}

impl Drop for ConnectionGuard {
    fn drop(&mut self) {
        self.metrics.dec_active_connections();

        // Debug: 打印连接关闭后的统计
        let active = self.metrics.get_active_connections();
        let total = self.metrics.get_total_connections();
        log::debug!("📊 连接关闭 | 总连接数: {} | 活跃连接: {}", total, active);
    }
}
