/// eBPF 流量统计
///
/// 使用 eBPF Per-CPU Map 实现零开销流量统计
///
/// 优势对比原子操作:
/// - 原子操作延迟: ~20ns
/// - Per-CPU 访问延迟: ~2ns (10x 提升)
/// - 无缓存行竞争
/// - 完全并行

use anyhow::{Context, Result};
use aya::maps::{HashMap as AyaHashMap, PerCpuArray};
use aya::Bpf;
use log::{debug, info};
use std::os::unix::io::RawFd;

use super::types::ConnectionStats;

/// 流量统计数据（用户态汇总）
#[derive(Debug, Clone, Default)]
pub struct TrafficStats {
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub packets_sent: u64,
    pub packets_received: u64,
}

impl TrafficStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_sent + self.packets_received
    }
}

/// eBPF 流量统计管理器
///
/// 使用真正的 eBPF Per-CPU Array 和 HashMap
pub struct EbpfStats {
    // eBPF Per-CPU Array: 全局流量统计（无锁并发）
    traffic_stats_map: PerCpuArray<&'static mut aya::maps::MapData, u64>,
    // eBPF HashMap: socket cookie → 连接统计
    connection_stats_map: AyaHashMap<&'static mut aya::maps::MapData, u64, ConnectionStats>,
}

impl EbpfStats {
    /// 创建新的统计管理器
    ///
    /// 从 Bpf 对象中获取 TRAFFIC_STATS 和 CONNECTION_STATS Maps
    pub fn new(bpf: &mut Bpf) -> Result<Self> {
        info!("初始化 eBPF 流量统计（使用真正的 eBPF Maps）");

        // 获取 TRAFFIC_STATS (PerCpuArray) 并立即转换生命周期
        let traffic_stats_map_static = {
            let traffic_stats_map: PerCpuArray<_, u64> = PerCpuArray::try_from(
                bpf.map_mut("TRAFFIC_STATS")
                    .context("无法找到 TRAFFIC_STATS")?
            ).context("无法创建 PerCpuArray 对象")?;

            // 立即转换生命周期，释放对 bpf 的借用
            unsafe { std::mem::transmute(traffic_stats_map) }
        };

        // 获取 CONNECTION_STATS (HashMap) 并立即转换生命周期
        let connection_stats_map_static = {
            let connection_stats_map: AyaHashMap<_, u64, ConnectionStats> = AyaHashMap::try_from(
                bpf.map_mut("CONNECTION_STATS")
                    .context("无法找到 CONNECTION_STATS")?
            ).context("无法创建 HashMap 对象")?;

            // 立即转换生命周期，释放对 bpf 的借用
            unsafe { std::mem::transmute(connection_stats_map) }
        };

        info!("✓ 成功获取 eBPF Maps: TRAFFIC_STATS, CONNECTION_STATS");

        Ok(Self {
            traffic_stats_map: traffic_stats_map_static,
            connection_stats_map: connection_stats_map_static,
        })
    }

    /// 记录发送的数据
    pub fn record_sent(&mut self, fd: RawFd, bytes: u64) -> Result<()> {
        debug!("记录发送: fd={}, bytes={}", fd, bytes);

        // 注意：实际的统计更新应该在 eBPF 程序中完成
        // 这里只是用户态的辅助接口

        // 获取 socket cookie
        let cookie = Self::fd_to_cookie(fd);

        // 尝试更新连接统计
        if let Ok(mut stats) = self.connection_stats_map.get(&cookie, 0) {
            stats.bytes_sent += bytes;
            stats.packets_sent += 1;
            let _ = self.connection_stats_map.insert(cookie, stats, 0);
        }

        Ok(())
    }

    /// 记录接收的数据
    pub fn record_received(&mut self, fd: RawFd, bytes: u64) -> Result<()> {
        debug!("记录接收: fd={}, bytes={}", fd, bytes);

        // 获取 socket cookie
        let cookie = Self::fd_to_cookie(fd);

        // 尝试更新连接统计
        if let Ok(mut stats) = self.connection_stats_map.get(&cookie, 0) {
            stats.bytes_received += bytes;
            stats.packets_received += 1;
            let _ = self.connection_stats_map.insert(cookie, stats, 0);
        }

        Ok(())
    }

    /// 获取全局统计（汇总所有 CPU）
    pub fn global_stats(&mut self) -> Result<TrafficStats> {
        let mut total = TrafficStats::default();

        // 汇总 Per-CPU 统计
        // Index 0: 发送字节数
        // Index 1: 接收字节数
        // Index 2: 发送包数
        // Index 3: 接收包数

        if let Ok(sent_bytes_percpu) = self.traffic_stats_map.get(&0, 0) {
            // 汇总所有 CPU 的值
            total.bytes_sent = sent_bytes_percpu.iter().sum();
        }

        if let Ok(recv_bytes_percpu) = self.traffic_stats_map.get(&1, 0) {
            total.bytes_received = recv_bytes_percpu.iter().sum();
        }

        if let Ok(sent_pkts_percpu) = self.traffic_stats_map.get(&2, 0) {
            total.packets_sent = sent_pkts_percpu.iter().sum();
        }

        if let Ok(recv_pkts_percpu) = self.traffic_stats_map.get(&3, 0) {
            total.packets_received = recv_pkts_percpu.iter().sum();
        }

        Ok(total)
    }

    /// 获取连接统计
    pub fn get_connection_stats(&mut self, fd: RawFd) -> Option<ConnectionStats> {
        let cookie = Self::fd_to_cookie(fd);
        self.connection_stats_map.get(&cookie, 0).ok()
    }

    /// 移除连接统计
    pub fn remove_connection(&mut self, fd: RawFd) -> Result<Option<ConnectionStats>> {
        let cookie = Self::fd_to_cookie(fd);

        // 先获取统计信息
        let stats = self.connection_stats_map.get(&cookie, 0).ok();

        // 然后删除
        let _ = self.connection_stats_map.remove(&cookie);

        Ok(stats)
    }

    /// FD 转 Cookie（临时实现）
    fn fd_to_cookie(fd: RawFd) -> u64 {
        let pid = std::process::id() as u64;
        ((fd as u64) << 32) | pid
    }

    /// 打印统计摘要
    pub fn print_summary(&mut self) {
        if let Ok(global) = self.global_stats() {
            info!("===== eBPF 流量统计 =====");
            info!("总发送: {} bytes ({} packets)",
                  global.bytes_sent, global.packets_sent);
            info!("总接收: {} bytes ({} packets)",
                  global.bytes_received, global.packets_received);
            info!("总流量: {} bytes ({} packets)",
                  global.total_bytes(), global.total_packets());
        }
    }
}

impl Drop for EbpfStats {
    fn drop(&mut self) {
        info!("eBPF 流量统计管理器销毁");
        self.print_summary();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_traffic_stats() {
        let mut stats = TrafficStats::new();

        stats.bytes_sent = 1000;
        stats.bytes_received = 2000;
        stats.packets_sent = 1;
        stats.packets_received = 1;

        assert_eq!(stats.bytes_sent, 1000);
        assert_eq!(stats.bytes_received, 2000);
        assert_eq!(stats.packets_sent, 1);
        assert_eq!(stats.packets_received, 1);
        assert_eq!(stats.total_bytes(), 3000);
        assert_eq!(stats.total_packets(), 2);
    }

    #[test]
    fn test_fd_to_cookie() {
        let cookie1 = EbpfStats::fd_to_cookie(10);
        let cookie2 = EbpfStats::fd_to_cookie(20);

        // Cookie 应该不同
        assert_ne!(cookie1, cookie2);

        // 同一 fd 应该生成相同 cookie
        let cookie1_again = EbpfStats::fd_to_cookie(10);
        assert_eq!(cookie1, cookie1_again);
    }
}
