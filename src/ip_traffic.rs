use log::{debug, info, warn};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::collections::HashMap;
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// IP 流量统计（内部类型，通过 Mutex 访问，无需 Arc 包装各字段）
#[derive(Debug)]
struct IpTrafficStats {
    bytes_received: AtomicU64,
    bytes_sent: AtomicU64,
    connections: AtomicU64,
}

impl IpTrafficStats {
    fn new() -> Self {
        Self {
            bytes_received: AtomicU64::new(0),
            bytes_sent: AtomicU64::new(0),
            connections: AtomicU64::new(0),
        }
    }

    fn add_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    fn add_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    fn inc_connections(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    fn get_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    fn get_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    fn get_total(&self) -> u64 {
        self.get_received() + self.get_sent()
    }

    fn get_connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }
}

/// 单个分片：独立加锁的 LRU 表
struct IpTrafficShard {
    stats: Mutex<LruCache<IpAddr, IpTrafficStats>>,
}

/// IP 流量追踪器
///
/// 内部按 IP 哈希分片存储（而不是单个全局 `Mutex<HashMap>`）：开启该功能后，
/// `record_connection`/`record_received`/`record_sent` 会在每个连接的关键路径上
/// 被调用，如果所有连接都抢同一把锁，会成为高并发下的争用热点。分片后不同 IP
/// 大概率落在不同分片，锁粒度从"全局"降到"1/N"。
#[derive(Clone)]
pub struct IpTrafficTracker {
    shards: Arc<Vec<IpTrafficShard>>,
    enabled: bool,
    /// 统计数据输出文件路径（可选）
    output_file: Option<String>,
    /// 持久化数据文件路径（可选，用于服务重启后恢复数据）
    persistence_file: Option<String>,
}

impl IpTrafficTracker {
    /// 创建新的 IP 流量追踪器
    ///
    /// # 参数
    /// * `max_tracked_ips` - 最大跟踪的 IP 数量（分摊到各分片，每分片用 LRU 淘汰）
    /// * `output_file` - 统计数据输出文件路径（可选，每次覆盖写入最新数据）
    /// * `persistence_file` - 持久化数据文件路径（可选，用于服务重启后恢复数据）
    pub fn new(max_tracked_ips: usize, output_file: Option<String>, persistence_file: Option<String>) -> Self {
        let shard_count = num_cpus::get().max(1).next_power_of_two().clamp(4, 32);
        // max(1) 防止 max_tracked_ips=0 时分片容量为 0 导致 unwrap panic（config 层已校验，此为防御性兜底）
        let per_shard_capacity = (max_tracked_ips.max(1) / shard_count).max(1);
        let shards: Vec<IpTrafficShard> = (0..shard_count)
            .map(|_| IpTrafficShard {
                stats: Mutex::new(LruCache::new(NonZeroUsize::new(per_shard_capacity).unwrap())),
            })
            .collect();

        let mut tracker = Self {
            shards: Arc::new(shards),
            enabled: true,
            output_file,
            persistence_file: persistence_file.clone(),
        };

        // 尝试从持久化文件加载数据
        if let Some(ref path) = persistence_file {
            if let Err(e) = tracker.load_from_file(path) {
                warn!("加载持久化数据失败: {}，将从空数据开始", e);
            } else {
                info!("✅ 成功从持久化文件加载数据: {}", path);
            }
        }

        tracker
    }

    /// 创建禁用的追踪器（不进行任何统计）
    pub fn disabled() -> Self {
        Self {
            shards: Arc::new(vec![IpTrafficShard {
                stats: Mutex::new(LruCache::new(NonZeroUsize::new(1).unwrap())),
            }]),
            enabled: false,
            output_file: None,
            persistence_file: None,
        }
    }

    /// 根据 IP 选择对应的分片
    fn shard_for(&self, ip: &IpAddr) -> &IpTrafficShard {
        let mut hasher = DefaultHasher::new();
        ip.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % self.shards.len();
        &self.shards[idx]
    }

    /// 记录连接
    pub fn record_connection(&self, ip: IpAddr) {
        if !self.enabled {
            return;
        }
        self.shard_for(&ip)
            .stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert(ip, IpTrafficStats::new)
            .inc_connections();
        debug!("IP {} 连接计数 +1", ip);
    }

    /// 记录接收流量（上传）
    pub fn record_received(&self, ip: IpAddr, bytes: u64) {
        if !self.enabled || bytes == 0 {
            return;
        }
        self.shard_for(&ip)
            .stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert(ip, IpTrafficStats::new)
            .add_received(bytes);
    }

    /// 记录发送流量（下载）
    pub fn record_sent(&self, ip: IpAddr, bytes: u64) {
        if !self.enabled || bytes == 0 {
            return;
        }
        self.shard_for(&ip)
            .stats
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get_or_insert(ip, IpTrafficStats::new)
            .add_sent(bytes);
    }

    /// 获取某个 IP 的统计信息
    pub fn get_stats(&self, ip: &IpAddr) -> Option<IpTrafficSnapshot> {
        if !self.enabled {
            return None;
        }

        let inner = self.shard_for(ip).stats.lock().unwrap_or_else(|e| e.into_inner());
        inner.peek(ip).map(|stats| IpTrafficSnapshot {
            ip: *ip,
            bytes_received: stats.get_received(),
            bytes_sent: stats.get_sent(),
            total_bytes: stats.get_total(),
            connections: stats.get_connections(),
        })
    }

    /// 获取所有 IP 的统计信息
    pub fn get_all_stats(&self) -> Vec<IpTrafficSnapshot> {
        if !self.enabled {
            return Vec::new();
        }

        let mut result = Vec::new();
        for shard in self.shards.iter() {
            let inner = shard.stats.lock().unwrap_or_else(|e| e.into_inner());
            result.extend(inner.iter().map(|(ip, stats)| IpTrafficSnapshot {
                ip: *ip,
                bytes_received: stats.get_received(),
                bytes_sent: stats.get_sent(),
                total_bytes: stats.get_total(),
                connections: stats.get_connections(),
            }));
        }
        result
    }

    /// 获取流量最大的 TOP N
    pub fn get_top_n(&self, n: usize) -> Vec<IpTrafficSnapshot> {
        let mut all_stats = self.get_all_stats();
        all_stats.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
        all_stats.truncate(n);
        all_stats
    }

    /// 打印统计摘要
    ///
    /// 注意：不在这里同步保存持久化数据——那是独立的定时任务
    /// （每 5 分钟一次，通过 `spawn_blocking` 执行，见 `server.rs`）的职责；
    /// 这里只负责日志输出和（可选的）统计文件写入，文件写入通过
    /// [`spawn_write_to_file`](Self::spawn_write_to_file) 丢给阻塞线程池，
    /// 避免同步磁盘 I/O 占用 tokio worker 线程、造成延迟毛刺。
    pub fn print_summary(&self, top_n: usize) {
        if !self.enabled {
            return;
        }

        let top_ips = self.get_top_n(top_n);

        if top_ips.is_empty() {
            info!("=== IP 流量统计（无数据） ===");
            self.spawn_write_to_file(Vec::new(), 0);
            return;
        }

        info!("=== IP 流量统计（TOP {}）===", top_ips.len());
        info!("{:<4} {:<40} {:>12} {:>12} {:>12} {:>8}",
              "排名", "IP 地址", "上传", "下载", "总流量", "连接数");
        info!("{}", "-".repeat(100));

        for (i, snapshot) in top_ips.iter().enumerate() {
            info!(
                "{:<4} {:<40} {:>12} {:>12} {:>12} {:>8}",
                i + 1,
                snapshot.ip,
                format_bytes(snapshot.bytes_received),
                format_bytes(snapshot.bytes_sent),
                format_bytes(snapshot.total_bytes),
                snapshot.connections
            );
        }

        let total_count = self.get_tracked_count();
        info!("{}", "-".repeat(100));
        info!("当前跟踪 IP 数量: {}", total_count);

        self.spawn_write_to_file(top_ips, total_count);
    }

    /// 把统计文件写入丢到阻塞线程池执行
    fn spawn_write_to_file(&self, top_ips: Vec<IpTrafficSnapshot>, total_count: usize) {
        let Some(path) = self.output_file.clone() else {
            return;
        };
        tokio::task::spawn_blocking(move || {
            if let Err(e) = write_ip_traffic_file(&path, &top_ips, total_count) {
                warn!("写入统计文件失败: {}", e);
            }
        });
    }

    /// 保存统计数据到持久化文件（JSON 格式）
    fn save_to_persistence_file_internal(&self, path: &str) -> std::io::Result<()> {
        use std::time::SystemTime;

        let mut stats_map = HashMap::new();
        for shard in self.shards.iter() {
            let inner = shard.stats.lock().unwrap_or_else(|e| e.into_inner());
            for (ip, stats) in inner.iter() {
                stats_map.insert(
                    ip.to_string(),
                    PersistedStats {
                        bytes_received: stats.get_received(),
                        bytes_sent: stats.get_sent(),
                        connections: stats.get_connections(),
                    },
                );
            }
        }

        let saved_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let data = PersistenceData {
            stats: stats_map,
            saved_at,
        };

        let json = serde_json::to_string_pretty(&data)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        file.flush()?;

        debug!("持久化数据已保存到: {}", path);
        Ok(())
    }

    /// 从持久化文件加载统计数据
    fn load_from_file(&mut self, path: &str) -> std::io::Result<()> {
        use std::time::SystemTime;

        let mut file = File::open(path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let data: PersistenceData = serde_json::from_str(&contents)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;

        let mut loaded_count = 0;

        for (ip_str, persisted_stats) in data.stats {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let stats = IpTrafficStats {
                    bytes_received: AtomicU64::new(persisted_stats.bytes_received),
                    bytes_sent: AtomicU64::new(persisted_stats.bytes_sent),
                    connections: AtomicU64::new(persisted_stats.connections),
                };
                self.shard_for(&ip)
                    .stats
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .put(ip, stats);
                loaded_count += 1;
            }
        }

        info!("从持久化文件加载了 {} 个 IP 的统计数据 (保存于 {} 秒前)",
            loaded_count,
            SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs()
                .saturating_sub(data.saved_at));

        Ok(())
    }

    /// 获取当前跟踪的 IP 数量
    pub fn get_tracked_count(&self) -> usize {
        if !self.enabled {
            return 0;
        }
        self.shards
            .iter()
            .map(|shard| shard.stats.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }

    /// 清空所有统计数据
    pub fn clear(&self) {
        if !self.enabled {
            return;
        }
        for shard in self.shards.iter() {
            shard.stats.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
        info!("IP 流量统计已清空");
    }

    /// 检查是否启用
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 手动保存持久化数据
    pub fn save_to_persistence_file(&self) {
        if !self.enabled {
            return;
        }

        if let Some(ref path) = self.persistence_file {
            if let Err(e) = self.save_to_persistence_file_internal(path) {
                warn!("保存持久化数据失败: {}", e);
            } else {
                debug!("持久化数据已保存");
            }
        }
    }
}

/// IP 流量统计快照
#[derive(Debug, Clone)]
pub struct IpTrafficSnapshot {
    pub ip: IpAddr,
    pub bytes_received: u64,
    pub bytes_sent: u64,
    pub total_bytes: u64,
    pub connections: u64,
}

/// 持久化数据结构（可序列化）
#[derive(Debug, Serialize, Deserialize)]
struct PersistenceData {
    /// 统计数据映射表 (IP -> 统计信息)
    stats: HashMap<String, PersistedStats>,
    /// 保存时间戳
    saved_at: u64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedStats {
    bytes_received: u64,
    bytes_sent: u64,
    connections: u64,
}

/// 写入 IP 流量统计文件（覆盖写入）
///
/// 独立成自由函数（不是 `IpTrafficTracker` 的方法）是为了方便在
/// `spawn_blocking` 闭包里调用而不必克隆整个 tracker。
fn write_ip_traffic_file(path: &str, top_ips: &[IpTrafficSnapshot], total_count: usize) -> std::io::Result<()> {
    use std::time::SystemTime;

    let mut file = File::create(path)?;

    if let Ok(duration) = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
        writeln!(file, "更新时间: {}", chrono::DateTime::<chrono::Local>::from(
            SystemTime::UNIX_EPOCH + duration
        ).format("%Y-%m-%d %H:%M:%S"))?;
    }
    writeln!(file)?;

    if top_ips.is_empty() {
        writeln!(file, "=== IP 流量统计（无数据） ===")?;
        return Ok(());
    }

    writeln!(file, "=== IP 流量统计（TOP {}）===", top_ips.len())?;
    writeln!(file, "{:<4} {:<40} {:>12} {:>12} {:>12} {:>8}",
             "排名", "IP 地址", "上传", "下载", "总流量", "连接数")?;
    writeln!(file, "{}", "-".repeat(100))?;

    for (i, snapshot) in top_ips.iter().enumerate() {
        writeln!(
            file,
            "{:<4} {:<40} {:>12} {:>12} {:>12} {:>8}",
            i + 1,
            snapshot.ip,
            format_bytes(snapshot.bytes_received),
            format_bytes(snapshot.bytes_sent),
            format_bytes(snapshot.total_bytes),
            snapshot.connections
        )?;
    }

    writeln!(file, "{}", "-".repeat(100))?;
    writeln!(file, "当前跟踪 IP 数量: {}", total_count)?;

    file.flush()?;
    Ok(())
}

/// 格式化字节数为人类可读格式
fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_traffic_tracker() {
        let tracker = IpTrafficTracker::new(100, None, None);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        tracker.record_connection(ip);
        tracker.record_connection(ip);

        tracker.record_received(ip, 1000);
        tracker.record_sent(ip, 2000);

        let stats = tracker.get_stats(&ip).unwrap();
        assert_eq!(stats.connections, 2);
        assert_eq!(stats.bytes_received, 1000);
        assert_eq!(stats.bytes_sent, 2000);
        assert_eq!(stats.total_bytes, 3000);
    }

    #[test]
    fn test_top_n() {
        let tracker = IpTrafficTracker::new(100, None, None);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();
        let ip3: IpAddr = "192.168.1.3".parse().unwrap();

        tracker.record_connection(ip1);
        tracker.record_sent(ip1, 1000);

        tracker.record_connection(ip2);
        tracker.record_sent(ip2, 3000);

        tracker.record_connection(ip3);
        tracker.record_sent(ip3, 2000);

        let top = tracker.get_top_n(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0].ip, ip2);
        assert_eq!(top[1].ip, ip3);
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
    }

    #[test]
    fn test_record_without_prior_connection() {
        let tracker = IpTrafficTracker::new(100, None, None);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        tracker.record_received(ip, 1000);
        tracker.record_sent(ip, 2000);

        let stats = tracker.get_stats(&ip).unwrap();
        assert_eq!(stats.connections, 0);
        assert_eq!(stats.bytes_received, 1000);
        assert_eq!(stats.bytes_sent, 2000);
    }

    #[test]
    fn test_disabled_tracker() {
        let tracker = IpTrafficTracker::disabled();
        assert!(!tracker.is_enabled());

        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        tracker.record_connection(ip);
        tracker.record_sent(ip, 1000);

        assert_eq!(tracker.get_tracked_count(), 0);
        assert!(tracker.get_stats(&ip).is_none());
    }

    #[tokio::test]
    async fn test_print_summary_writes_file_via_blocking_task() {
        // print_summary 内部通过 spawn_blocking 异步写文件（不阻塞调用线程），
        // 这里验证任务确实执行了、文件确实写出来了，而不只是编译通过。
        let path = std::env::temp_dir().join(format!(
            "sni_proxy_ip_traffic_test_{}.txt",
            std::process::id()
        ));
        let path_str = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        let tracker = IpTrafficTracker::new(100, Some(path_str), None);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();
        tracker.record_connection(ip);
        tracker.record_sent(ip, 12345);

        tracker.print_summary(10);

        // spawn_blocking 是 fire-and-forget，给它一点时间跑完
        for _ in 0..20 {
            if path.exists() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }

        let contents = std::fs::read_to_string(&path).expect("统计文件应已写入");
        assert!(contents.contains("192.168.1.1"));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn test_sharding_preserves_all_entries() {
        // 多个不同 IP 分布在不同分片时，聚合类接口（get_all_stats/get_tracked_count/
        // save 相关逻辑依赖的遍历）应仍然能看到所有条目，不因分片丢数据
        let tracker = IpTrafficTracker::new(1000, None, None);
        let ips: Vec<IpAddr> = (0..50)
            .map(|i| format!("10.0.{}.{}", i / 256, i % 256).parse().unwrap())
            .collect();

        for ip in &ips {
            tracker.record_connection(*ip);
        }

        assert_eq!(tracker.get_tracked_count(), ips.len());
        assert_eq!(tracker.get_all_stats().len(), ips.len());
    }
}
