use log::info;
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
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

        let mut data = self.data.lock().unwrap();
        data.entry(domain.to_string())
            .or_insert_with(HashSet::new)
            .insert(ip);
    }

    /// 获取统计信息
    pub fn get_stats(&self) -> (usize, usize) {
        let data = self.data.lock().unwrap();
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

        let data = self.data.lock().unwrap();

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
        for domain in domains {
            if let Some(ips) = data.get(domain) {
                // 将 IP 转换为 Vec 并排序
                let mut ip_list: Vec<_> = ips.iter().collect();
                ip_list.sort();

                // 格式化输出
                let ip_str = ip_list
                    .iter()
                    .map(|ip| ip.to_string())
                    .collect::<Vec<_>>()
                    .join(", ");

                writeln!(file, "{} -> {}", domain, ip_str)?;
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
