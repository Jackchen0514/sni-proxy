/// eBPF 共享数据类型
///
/// 这些类型必须与 ebpf/src/main.rs 中的内核态定义完全匹配

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// DNS 记录（与内核态结构体匹配）
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct DnsRecord {
    /// IP 地址类型: 4=IPv4, 6=IPv6
    pub ip_type: u8,
    /// IPv4 地址 (网络字节序)
    pub ipv4: [u8; 4],
    /// IPv6 地址 (网络字节序)
    pub ipv6: [u8; 16],
    /// 时间戳 (秒)
    pub timestamp: u64,
    /// TTL (秒)
    pub ttl: u32,
    /// 保留字段
    pub _reserved: u32,
}

// 实现 Pod trait，表明这个类型可以安全地以字节形式传输
unsafe impl aya::Pod for DnsRecord {}

impl DnsRecord {
    /// 从 IpAddr 创建 DNS 记录
    pub fn from_ip(ip: IpAddr, ttl: u32) -> Self {
        match ip {
            IpAddr::V4(ipv4) => Self {
                ip_type: 4,
                ipv4: ipv4.octets(),
                ipv6: [0; 16],
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                ttl,
                _reserved: 0,
            },
            IpAddr::V6(ipv6) => Self {
                ip_type: 6,
                ipv4: [0; 4],
                ipv6: ipv6.octets(),
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                ttl,
                _reserved: 0,
            },
        }
    }

    /// 转换为 IpAddr
    pub fn to_ip(&self) -> Option<IpAddr> {
        match self.ip_type {
            4 => Some(IpAddr::V4(Ipv4Addr::from(self.ipv4))),
            6 => Some(IpAddr::V6(Ipv6Addr::from(self.ipv6))),
            _ => None,
        }
    }

    /// 检查是否过期
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.timestamp + self.ttl as u64
    }
}

/// 连接统计信息（与内核态结构体匹配）
#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct ConnectionStats {
    /// 发送字节数
    pub bytes_sent: u64,
    /// 接收字节数
    pub bytes_received: u64,
    /// 发送包数
    pub packets_sent: u64,
    /// 接收包数
    pub packets_received: u64,
    /// 连接建立时间
    pub start_time: u64,
}

// 实现 Pod trait，表明这个类型可以安全地以字节形式传输
unsafe impl aya::Pod for ConnectionStats {}

impl ConnectionStats {
    pub fn new() -> Self {
        Self {
            bytes_sent: 0,
            bytes_received: 0,
            packets_sent: 0,
            packets_received: 0,
            start_time: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_received
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_sent + self.packets_received
    }
}

// 确保结构体大小匹配
#[cfg(test)]
mod tests {
    use super::*;
    use std::mem;

    #[test]
    fn test_struct_sizes() {
        // DNS Record 大小检查
        assert_eq!(mem::size_of::<DnsRecord>(), 40);

        // Connection Stats 大小检查
        assert_eq!(mem::size_of::<ConnectionStats>(), 40);
    }

    #[test]
    fn test_dns_record_conversion() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let record = DnsRecord::from_ip(ip, 300);

        assert_eq!(record.ip_type, 4);
        assert_eq!(record.to_ip(), Some(ip));
        assert!(!record.is_expired());
    }
}
