use log::info;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};
use std::fs::File;
use std::io::Write as IoWrite;

/// 域名-IP 追踪器
/// 记录所有通过代理的域名及其解析的 IP 地址（去重）
#[derive(Clone)]
pub struct DomainIpTracker {
    /// 域名到 IP 地址集合的映射
    data: Arc<Mutex<HashMap<String, HashSet<IpAddr>>>>,
    /// 输出文件路径
    output_file: Option<String>,
    /// 是否启用
    enabled: bool,
}

impl DomainIpTracker {
    /// 创建新的域名-IP 追踪器（启用）
    pub fn new(output_file: Option<String>) -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
            output_file,
            enabled: true,
        }
    }

    /// 创建禁用的追踪器
    pub fn disabled() -> Self {
        Self {
            data: Arc::new(Mutex::new(HashMap::new())),
            output_file: None,
            enabled: false,
        }
    }

    /// 检查是否启用
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// 记录域名和对应的 IP 地址
    pub fn record(&self, domain: &str, ip: IpAddr) {
        if !self.enabled {
            return;
        }

        let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
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
        let mut data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        data.entry(domain.to_string())
            .or_insert_with(HashSet::new)
            .insert(socks5_marker);
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> (usize, usize) {
        let data = self.data.lock().unwrap_or_else(|e| e.into_inner());
        let domain_count = data.len();
        let ip_count: usize = data.values().map(|ips| ips.len()).sum();
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

        let data = self.data.lock().unwrap_or_else(|e| e.into_inner());

        // 创建或覆盖文件
        let mut file = File::create(output_path)?;

        // 写入表头
        writeln!(file, "# SNI 代理域名-IP 映射表")?;
        writeln!(file, "# 格式: 域名 -> IP地址列表")?;
        writeln!(file, "# 生成时间: {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))?;
        writeln!(file, "# 总域名数: {}", data.len())?;
        writeln!(file)?;

        // 按域名排序
        let mut domains: Vec<_> = data.keys().collect();
        domains.sort();

        // 写入每个域名及其 IP 列表
        let socks5_marker = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
        for domain in domains {
            if let Some(ips) = data.get(domain) {
                // 将 IP 转换为 Vec 并排序
                let mut ip_list: Vec<_> = ips.iter().collect();
                ip_list.sort();

                // 检查是否只包含 SOCKS5 标记
                if ip_list.len() == 1 && *ip_list[0] == socks5_marker {
                    // SOCKS5 流量
                    writeln!(file, "{} -> [SOCKS5]", domain)?;
                } else {
                    // 格式化输出，过滤掉 SOCKS5 标记
                    let ip_str = ip_list
                        .iter()
                        .filter(|ip| ***ip != socks5_marker)
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(", ");

                    if ip_str.is_empty() {
                        // 只有 SOCKS5 标记（理论上不会到这里）
                        writeln!(file, "{} -> [SOCKS5]", domain)?;
                    } else if ips.contains(&socks5_marker) {
                        // 既有直连 IP 又有 SOCKS5
                        writeln!(file, "{} -> {} [也通过SOCKS5]", domain, ip_str)?;
                    } else {
                        // 仅直连 IP
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
