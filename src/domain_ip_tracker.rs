use log::info;
use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::hash::{Hash, Hasher};
use std::io::Write as IoWrite;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

/// 单个分片：独立加锁的域名 -> IP 集合映射
struct DomainIpShard {
    data: Mutex<HashMap<String, HashSet<IpAddr>>>,
}

/// 域名-IP 追踪器
/// 记录所有通过代理的域名及其解析的 IP 地址（去重）
///
/// 内部按域名哈希分片存储（而不是单个全局 `Mutex<HashMap>`）：开启该功能后，
/// `record`/`record_socks5` 会在每个连接建连时被调用，所有连接抢同一把锁会成为
/// 高并发下的争用热点。分片后不同域名大概率落在不同分片，锁粒度从"全局"降到"1/N"。
#[derive(Clone)]
pub struct DomainIpTracker {
    shards: Arc<Vec<DomainIpShard>>,
    /// 输出文件路径
    output_file: Option<String>,
    /// 是否启用
    enabled: bool,
}

impl DomainIpTracker {
    /// 创建新的域名-IP 追踪器（启用）
    pub fn new(output_file: Option<String>) -> Self {
        let shard_count = num_cpus::get().max(1).next_power_of_two().clamp(4, 32);
        Self {
            shards: Arc::new(
                (0..shard_count)
                    .map(|_| DomainIpShard {
                        data: Mutex::new(HashMap::new()),
                    })
                    .collect(),
            ),
            output_file,
            enabled: true,
        }
    }

    /// 创建禁用的追踪器
    pub fn disabled() -> Self {
        Self {
            shards: Arc::new(vec![DomainIpShard {
                data: Mutex::new(HashMap::new()),
            }]),
            output_file: None,
            enabled: false,
        }
    }

    /// 检查是否启用
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 根据域名选择对应的分片
    fn shard_for(&self, domain: &str) -> &DomainIpShard {
        let mut hasher = DefaultHasher::new();
        domain.hash(&mut hasher);
        let idx = (hasher.finish() as usize) % self.shards.len();
        &self.shards[idx]
    }

    /// 记录域名和对应的 IP 地址
    pub fn record(&self, domain: &str, ip: IpAddr) {
        if !self.enabled {
            return;
        }

        let mut data = self.shard_for(domain).data.lock().unwrap_or_else(|e| e.into_inner());
        data.entry(domain.to_string())
            .or_insert_with(HashSet::new)
            .insert(ip);
    }

    /// 记录仅域名（用于 SOCKS5 流量，无法获取实际 IP）
    /// 使用 0.0.0.0 作为占位符表示通过 SOCKS5
    pub fn record_socks5(&self, domain: &str) {
        if !self.enabled {
            return;
        }

        // 使用 0.0.0.0 作为 SOCKS5 流量的标记
        let socks5_marker = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        let mut data = self.shard_for(domain).data.lock().unwrap_or_else(|e| e.into_inner());
        data.entry(domain.to_string())
            .or_insert_with(HashSet::new)
            .insert(socks5_marker);
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> (usize, usize) {
        let mut domain_count = 0;
        let mut ip_count = 0;
        for shard in self.shards.iter() {
            let data = shard.data.lock().unwrap_or_else(|e| e.into_inner());
            domain_count += data.len();
            ip_count += data.values().map(|ips| ips.len()).sum::<usize>();
        }
        (domain_count, ip_count)
    }

    /// 保存到文件
    pub fn save_to_file(&self) -> Result<(), std::io::Error> {
        if !self.enabled {
            return Ok(());
        }

        let output_path = match &self.output_file {
            Some(path) => path,
            None => return Ok(()), // 没有指定输出文件，直接返回
        };

        // 合并所有分片的数据以便统一排序输出（后台周期任务，不在连接热路径上，
        // 多一次拷贝可以接受）
        let mut merged: HashMap<String, HashSet<IpAddr>> = HashMap::new();
        for shard in self.shards.iter() {
            let data = shard.data.lock().unwrap_or_else(|e| e.into_inner());
            for (domain, ips) in data.iter() {
                merged
                    .entry(domain.clone())
                    .or_insert_with(HashSet::new)
                    .extend(ips.iter().copied());
            }
        }

        // 创建或覆盖文件
        let mut file = File::create(output_path)?;

        // 写入表头
        writeln!(file, "# SNI 代理域名-IP 映射表")?;
        writeln!(file, "# 格式: 域名 -> IP地址列表")?;
        writeln!(file, "# 生成时间: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))?;
        writeln!(file, "# 总域名数: {}", merged.len())?;
        writeln!(file)?;

        // 按域名排序
        let mut domains: Vec<_> = merged.keys().collect();
        domains.sort();

        // 写入每个域名及其 IP 列表
        let socks5_marker = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        for domain in domains {
            if let Some(ips) = merged.get(domain) {
                let mut ip_list: Vec<_> = ips.iter().collect();
                ip_list.sort();

                if ip_list.len() == 1 && *ip_list[0] == socks5_marker {
                    writeln!(file, "{} -> [SOCKS5]", domain)?;
                } else {
                    let ip_str = ip_list
                        .iter()
                        .filter(|ip| ***ip != socks5_marker)
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");

                    if ip_str.is_empty() {
                        writeln!(file, "{} -> [SOCKS5]", domain)?;
                    } else if ips.contains(&socks5_marker) {
                        writeln!(file, "{} -> {} [也通过SOCKS5]", domain, ip_str)?;
                    } else {
                        writeln!(file, "{} -> {}", domain, ip_str)?;
                    }
                }
            }
        }

        info!("✅ 域名-IP 映射已保存到: {}", output_path);
        Ok(())
    }

    /// 打印摘要
    pub fn print_summary(&self) {
        if !self.enabled {
            return;
        }

        let (domain_count, ip_count) = self.get_stats();
        info!("📊 域名-IP 统计: {} 个域名, {} 个 IP", domain_count, ip_count);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_and_stats() {
        let tracker = DomainIpTracker::new(None);
        let ip1: IpAddr = "1.2.3.4".parse().unwrap();
        let ip2: IpAddr = "1.2.3.5".parse().unwrap();

        tracker.record("example.com", ip1);
        tracker.record("example.com", ip2);
        tracker.record("other.com", ip1);

        let (domain_count, ip_count) = tracker.get_stats();
        assert_eq!(domain_count, 2);
        assert_eq!(ip_count, 3);
    }

    #[test]
    fn test_disabled_tracker() {
        let tracker = DomainIpTracker::disabled();
        assert!(!tracker.is_enabled());

        tracker.record("example.com", "1.2.3.4".parse().unwrap());
        let (domain_count, ip_count) = tracker.get_stats();
        assert_eq!(domain_count, 0);
        assert_eq!(ip_count, 0);
    }

    #[test]
    fn test_sharding_preserves_all_domains() {
        let tracker = DomainIpTracker::new(None);
        for i in 0..50 {
            tracker.record(&format!("host{}.example.com", i), "1.2.3.4".parse().unwrap());
        }

        let (domain_count, _) = tracker.get_stats();
        assert_eq!(domain_count, 50);
    }
}
