use log::{debug, info, warn};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Write};
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

/// IP 流量统计
#[derive(Debug, Clone)]
pub struct IpTrafficStats {
    /// 接收字节数（上传）
    bytes_received: Arc<AtomicU64>,
    /// 发送字节数（下载）
    bytes_sent: Arc<AtomicU64>,
    /// 连接次数
    connections: Arc<AtomicU64>,
}

impl IpTrafficStats {
    fn new() -> Self {
        Self {
            bytes_received: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            connections: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn add_received(&self, bytes: u64) {
        self.bytes_received.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_sent(&self, bytes: u64) {
        self.bytes_sent.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn inc_connections(&self) {
        self.connections.fetch_add(1, Ordering::Relaxed);
    }

    pub fn get_received(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }

    pub fn get_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    pub fn get_total(&self) -> u64 {
        self.get_received() + self.get_sent()
    }

    pub fn get_connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }
}

/// IP 流量追踪器
#[derive(Clone)]
pub struct IpTrafficTracker {
    inner: Arc<Mutex<IpTrafficTrackerInner>>,
    enabled: bool,
    /// 统计数据输出文件路径（可选）
    output_file: Option<String>,
    /// 持久化数据文件路径（可选，用于服务重启后恢复数据）
    persistence_file: Option<String>,
}

struct IpTrafficTrackerInner {
    /// IP 流量统计表（使用 LRU 缓存限制内存）
    stats: LruCache<IpAddr, IpTrafficStats>,
    /// 最大跟踪 IP 数量
    #[allow(dead_code)]
    max_tracked_ips: usize,
}

impl IpTrafficTracker {
    /// 创建新的 IP 流量追踪器
    ///
    /// # 参数
    /// * `max_tracked_ips` - 最大跟踪的 IP 数量（使用 LRU，超过后会淘汰最少使用的）
    /// * `output_file` - 统计数据输出文件路径（可选，每次覆盖写入最新数据）
    /// * `persistence_file` - 持久化数据文件路径（可选，用于服务重启后恢复数据）
    pub fn new(max_tracked_ips: usize, output_file: Option<String>, persistence_file: Option<String>) -> Self {
        let capacity = NonZeroUsize::new(max_tracked_ips).unwrap();

        let mut tracker = Self {
            inner: Arc::new(Mutex::new(IpTrafficTrackerInner {
                stats: LruCache::new(capacity),
                max_tracked_ips,
            })),
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
            inner: Arc::new(Mutex::new(IpTrafficTrackerInner {
                stats: LruCache::new(NonZeroUsize::new(1).unwrap()),
                max_tracked_ips: 0,
            })),
            enabled: false,
            output_file: None,
            persistence_file: None,
        }
    }

    /// 记录连接
    pub fn record_connection(&self, ip: IpAddr) {
        if !self.enabled {
            return;
        }

        let mut inner = self.inner.lock().unwrap();
        let stats = inner
            .stats
            .get_or_insert(ip, || IpTrafficStats::new())
            .clone();
        drop(inner); // 尽早释放锁

        stats.inc_connections();
        debug!("IP {} 连接计数 +1", ip);
    }

    /// 记录接收流量（上传）
    pub fn record_received(&self, ip: IpAddr, bytes: u64) {
        if !self.enabled || bytes == 0 {
            return;
        }

        let mut inner = self.inner.lock().unwrap();
        if let Some(stats) = inner.stats.get(&ip) {
            let stats = stats.clone();
            drop(inner);
            stats.add_received(bytes);
        }
    }

    /// 记录发送流量（下载）
    pub fn record_sent(&self, ip: IpAddr, bytes: u64) {
        if !self.enabled || bytes == 0 {
            return;
        }

        let mut inner = self.inner.lock().unwrap();
        if let Some(stats) = inner.stats.get(&ip) {
            let stats = stats.clone();
            drop(inner);
            stats.add_sent(bytes);
        }
    }

    /// 获取某个 IP 的统计信息
    pub fn get_stats(&self, ip: &IpAddr) -> Option<IpTrafficSnapshot> {
        if !self.enabled {
            return None;
        }

        let inner = self.inner.lock().unwrap();
        inner.stats.peek(ip).map(|stats| IpTrafficSnapshot {
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

        let inner = self.inner.lock().unwrap();
        inner
            .stats
            .iter()
            .map(|(ip, stats)| IpTrafficSnapshot {
                ip: *ip,
                bytes_received: stats.get_received(),
                bytes_sent: stats.get_sent(),
                total_bytes: stats.get_total(),
                connections: stats.get_connections(),
            })
            .collect()
    }

    /// 获取流量最大的 TOP N
    pub fn get_top_n(&self, n: usize) -> Vec<IpTrafficSnapshot> {
        let mut all_stats = self.get_all_stats();
        all_stats.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
        all_stats.truncate(n);
        all_stats
    }

    /// 打印统计摘要
    pub fn print_summary(&self, top_n: usize) {
        if !self.enabled {
            return;
        }

        let top_ips = self.get_top_n(top_n);

        if top_ips.is_empty() {
            info!("=== IP 流量统计（无数据） ===");
            // 写入空数据到文件
            if let Some(ref path) = self.output_file {
                if let Err(e) = self.write_to_file(path, &[], 0) {
                    warn!("写入统计文件失败: {}", e);
                }
            }
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

        // 计算总计
        let total_count = self.get_tracked_count();
        info!("{}", "-".repeat(100));
        info!("当前跟踪 IP 数量: {}", total_count);

        // 写入到文件（如果配置了）
        if let Some(ref path) = self.output_file {
            if let Err(e) = self.write_to_file(path, &top_ips, total_count) {
                warn!("写入统计文件失败: {}", e);
            }
        }

        // 保存到持久化文件（如果配置了）
        if let Some(ref path) = self.persistence_file {
            if let Err(e) = self.save_to_persistence_file_internal(path) {
                warn!("保存持久化数据失败: {}", e);
            }
        }
    }

    /// 写入统计数据到文件（覆盖写入）
    fn write_to_file(&self, path: &str, top_ips: &[IpTrafficSnapshot], total_count: usize) -> std::io::Result<()> {
        use std::time::SystemTime;

        let mut file = File::create(path)?;

        // 写入时间戳
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

    /// 保存统计数据到持久化文件（JSON 格式）
    fn save_to_persistence_file_internal(&self, path: &str) -> std::io::Result<()> {
        use std::time::SystemTime;

        let inner = self.inner.lock().unwrap();

        // 转换为可序列化的格式
        let mut stats_map = HashMap::new();
        for (ip, stats) in inner.stats.iter() {
            stats_map.insert(
                ip.to_string(),
                PersistedStats {
                    bytes_received: stats.get_received(),
                    bytes_sent: stats.get_sent(),
                    connections: stats.get_connections(),
                },
            );
        }

        let saved_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let data = PersistenceData {
            stats: stats_map,
            saved_at,
        };

        drop(inner); // 释放锁

        // 序列化并写入文件
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

        let mut inner = self.inner.lock().unwrap();
        let mut loaded_count = 0;

        for (ip_str, persisted_stats) in data.stats {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                let stats = IpTrafficStats {
                    bytes_received: Arc::new(AtomicU64::new(persisted_stats.bytes_received)),
                    bytes_sent: Arc::new(AtomicU64::new(persisted_stats.bytes_sent)),
                    connections: Arc::new(AtomicU64::new(persisted_stats.connections)),
                };
                inner.stats.put(ip, stats);
                loaded_count += 1;
            }
        }

        drop(inner);

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
        self.inner.lock().unwrap().stats.len()
    }

    /// 清空所有统计数据
    pub fn clear(&self) {
        if !self.enabled {
            return;
        }
        let mut inner = self.inner.lock().unwrap();
        inner.stats.clear();
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
        let tracker = IpTrafficTracker::new(100, None);
        let ip: IpAddr = "192.168.1.1".parse().unwrap();

        // 记录连接
        tracker.record_connection(ip);
        tracker.record_connection(ip);

        // 记录流量
        tracker.record_received(ip, 1000);
        tracker.record_sent(ip, 2000);

        // 获取统计
        let stats = tracker.get_stats(&ip).unwrap();
        assert_eq!(stats.connections, 2);
        assert_eq!(stats.bytes_received, 1000);
        assert_eq!(stats.bytes_sent, 2000);
        assert_eq!(stats.total_bytes, 3000);
    }

    #[test]
    fn test_top_n() {
        let tracker = IpTrafficTracker::new(100, None);

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
        assert_eq!(top[0].ip, ip2); // 3000 bytes
        assert_eq!(top[1].ip, ip3); // 2000 bytes
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(500), "500 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1024 * 1024), "1.00 MB");
        assert_eq!(format_bytes(1024 * 1024 * 1024), "1.00 GB");
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
}
