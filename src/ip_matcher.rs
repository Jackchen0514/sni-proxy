use log::{info, warn};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::collections::HashSet;

/// IP 匹配器，支持单个 IP 和 CIDR 网段匹配
#[derive(Debug, Clone)]
pub struct IpMatcher {
    /// 精确匹配的 IP 地址列表
    exact_ips: HashSet<IpAddr>,
    /// CIDR 网段列表（IPv4）
    ipv4_networks: Vec<Ipv4Network>,
    /// CIDR 网段列表（IPv6）
    ipv6_networks: Vec<Ipv6Network>,
}

/// IPv4 网段
#[derive(Debug, Clone)]
struct Ipv4Network {
    network: u32,
    mask: u32,
    #[allow(dead_code)]
    prefix_len: u8,
}

/// IPv6 网段
#[derive(Debug, Clone)]
struct Ipv6Network {
    network: u128,
    mask: u128,
    #[allow(dead_code)]
    prefix_len: u8,
}

impl IpMatcher {
    /// 创建新的 IP 匹配器
    ///
    /// # 参数
    /// * `ip_patterns` - IP 模式列表，可以是：
    ///   - 单个 IP 地址：`192.168.1.1` 或 `::1`
    ///   - CIDR 网段：`192.168.1.0/24` 或 `2001:db8::/32`
    pub fn new(ip_patterns: Vec<String>) -> Self {
        let mut exact_ips = HashSet::new();
        let mut ipv4_networks = Vec::new();
        let mut ipv6_networks = Vec::new();

        for pattern in ip_patterns {
            let pattern = pattern.trim();

            if pattern.is_empty() {
                continue;
            }

            // 检查是否是 CIDR 格式
            if pattern.contains('/') {
                Self::parse_cidr(pattern, &mut ipv4_networks, &mut ipv6_networks);
            } else {
                // 尝试解析为单个 IP 地址
                match pattern.parse::<IpAddr>() {
                    Ok(ip) => {
                        exact_ips.insert(ip);
                        info!("添加 IP 白名单: {}", ip);
                    }
                    Err(_) => {
                        warn!("无效的 IP 地址: {}", pattern);
                    }
                }
            }
        }

        Self {
            exact_ips,
            ipv4_networks,
            ipv6_networks,
        }
    }

    /// 解析 CIDR 格式的网段
    fn parse_cidr(
        cidr: &str,
        ipv4_networks: &mut Vec<Ipv4Network>,
        ipv6_networks: &mut Vec<Ipv6Network>,
    ) {
        let parts: Vec<&str> = cidr.split('/').collect();
        if parts.len() != 2 {
            warn!("无效的 CIDR 格式: {}", cidr);
            return;
        }

        let ip_str = parts[0].trim();
        let prefix_str = parts[1].trim();

        // 解析前缀长度
        let prefix_len = match prefix_str.parse::<u8>() {
            Ok(len) => len,
            Err(_) => {
                warn!("无效的 CIDR 前缀长度: {}", cidr);
                return;
            }
        };

        // 尝试解析为 IPv4
        if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
            if prefix_len > 32 {
                warn!("IPv4 CIDR 前缀长度无效 (>32): {}", cidr);
                return;
            }

            let ip_u32 = u32::from(ip);
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u32 << (32 - prefix_len)
            };
            let network = ip_u32 & mask;

            ipv4_networks.push(Ipv4Network {
                network,
                mask,
                prefix_len,
            });

            let network_addr = Ipv4Addr::from(network);
            info!("添加 IPv4 网段白名单: {}/{} (网络地址: {})", ip_str, prefix_len, network_addr);
        }
        // 尝试解析为 IPv6
        else if let Ok(ip) = ip_str.parse::<Ipv6Addr>() {
            if prefix_len > 128 {
                warn!("IPv6 CIDR 前缀长度无效 (>128): {}", cidr);
                return;
            }

            let ip_u128 = u128::from(ip);
            let mask = if prefix_len == 0 {
                0
            } else {
                !0u128 << (128 - prefix_len)
            };
            let network = ip_u128 & mask;

            ipv6_networks.push(Ipv6Network {
                network,
                mask,
                prefix_len,
            });

            let network_addr = Ipv6Addr::from(network);
            info!("添加 IPv6 网段白名单: {}/{} (网络地址: {})", ip_str, prefix_len, network_addr);
        } else {
            warn!("无效的 IP 地址: {}", ip_str);
        }
    }

    /// 检查 IP 是否匹配白名单
    #[inline]
    pub fn matches(&self, ip: IpAddr) -> bool {
        // 先检查精确匹配（O(1)）
        if self.exact_ips.contains(&ip) {
            return true;
        }

        // 检查 CIDR 网段匹配
        match ip {
            IpAddr::V4(ipv4) => {
                let ip_u32 = u32::from(ipv4);
                for network in &self.ipv4_networks {
                    if (ip_u32 & network.mask) == network.network {
                        return true;
                    }
                }
            }
            IpAddr::V6(ipv6) => {
                let ip_u128 = u128::from(ipv6);
                for network in &self.ipv6_networks {
                    if (ip_u128 & network.mask) == network.network {
                        return true;
                    }
                }
            }
        }

        false
    }

    /// 检查是否没有配置任何 IP 白名单（即禁用 IP 白名单功能）
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.exact_ips.is_empty() && self.ipv4_networks.is_empty() && self.ipv6_networks.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_ipv4_match() {
        let matcher = IpMatcher::new(vec![
            "192.168.1.1".to_string(),
            "10.0.0.1".to_string(),
        ]);

        assert!(matcher.matches("192.168.1.1".parse().unwrap()));
        assert!(matcher.matches("10.0.0.1".parse().unwrap()));
        assert!(!matcher.matches("192.168.1.2".parse().unwrap()));
        assert!(!matcher.matches("10.0.0.2".parse().unwrap()));
    }

    #[test]
    fn test_exact_ipv6_match() {
        let matcher = IpMatcher::new(vec![
            "::1".to_string(),
            "2001:db8::1".to_string(),
        ]);

        assert!(matcher.matches("::1".parse().unwrap()));
        assert!(matcher.matches("2001:db8::1".parse().unwrap()));
        assert!(!matcher.matches("::2".parse().unwrap()));
        assert!(!matcher.matches("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn test_ipv4_cidr_match() {
        let matcher = IpMatcher::new(vec![
            "192.168.1.0/24".to_string(),
            "10.0.0.0/8".to_string(),
        ]);

        // 192.168.1.0/24 应该匹配 192.168.1.0 到 192.168.1.255
        assert!(matcher.matches("192.168.1.1".parse().unwrap()));
        assert!(matcher.matches("192.168.1.100".parse().unwrap()));
        assert!(matcher.matches("192.168.1.255".parse().unwrap()));
        assert!(!matcher.matches("192.168.2.1".parse().unwrap()));

        // 10.0.0.0/8 应该匹配 10.0.0.0 到 10.255.255.255
        assert!(matcher.matches("10.0.0.1".parse().unwrap()));
        assert!(matcher.matches("10.255.255.255".parse().unwrap()));
        assert!(!matcher.matches("11.0.0.1".parse().unwrap()));
    }

    #[test]
    fn test_ipv6_cidr_match() {
        let matcher = IpMatcher::new(vec![
            "2001:db8::/32".to_string(),
            "fe80::/10".to_string(),
        ]);

        // 2001:db8::/32
        assert!(matcher.matches("2001:db8::1".parse().unwrap()));
        assert!(matcher.matches("2001:db8:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!matcher.matches("2001:db9::1".parse().unwrap()));

        // fe80::/10 (link-local)
        assert!(matcher.matches("fe80::1".parse().unwrap()));
        assert!(matcher.matches("febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
        assert!(!matcher.matches("fec0::1".parse().unwrap()));
    }

    #[test]
    fn test_mixed_exact_and_cidr() {
        let matcher = IpMatcher::new(vec![
            "192.168.1.1".to_string(),
            "192.168.2.0/24".to_string(),
            "::1".to_string(),
            "2001:db8::/32".to_string(),
        ]);

        // 精确匹配
        assert!(matcher.matches("192.168.1.1".parse().unwrap()));
        assert!(matcher.matches("::1".parse().unwrap()));

        // CIDR 匹配
        assert!(matcher.matches("192.168.2.100".parse().unwrap()));
        assert!(matcher.matches("2001:db8::5".parse().unwrap()));

        // 不匹配
        assert!(!matcher.matches("192.168.1.2".parse().unwrap()));
        assert!(!matcher.matches("192.168.3.1".parse().unwrap()));
        assert!(!matcher.matches("::2".parse().unwrap()));
        assert!(!matcher.matches("2001:db9::1".parse().unwrap()));
    }

    #[test]
    fn test_localhost() {
        let matcher = IpMatcher::new(vec![
            "127.0.0.0/8".to_string(),
            "::1".to_string(),
        ]);

        // IPv4 localhost
        assert!(matcher.matches("127.0.0.1".parse().unwrap()));
        assert!(matcher.matches("127.0.0.255".parse().unwrap()));
        assert!(matcher.matches("127.255.255.255".parse().unwrap()));

        // IPv6 localhost
        assert!(matcher.matches("::1".parse().unwrap()));

        // 非 localhost
        assert!(!matcher.matches("192.168.1.1".parse().unwrap()));
        assert!(!matcher.matches("::2".parse().unwrap()));
    }

    #[test]
    fn test_private_networks() {
        let matcher = IpMatcher::new(vec![
            "10.0.0.0/8".to_string(),
            "172.16.0.0/12".to_string(),
            "192.168.0.0/16".to_string(),
        ]);

        // 10.0.0.0/8
        assert!(matcher.matches("10.0.0.1".parse().unwrap()));
        assert!(matcher.matches("10.255.255.255".parse().unwrap()));

        // 172.16.0.0/12
        assert!(matcher.matches("172.16.0.1".parse().unwrap()));
        assert!(matcher.matches("172.31.255.255".parse().unwrap()));
        assert!(!matcher.matches("172.32.0.1".parse().unwrap()));

        // 192.168.0.0/16
        assert!(matcher.matches("192.168.0.1".parse().unwrap()));
        assert!(matcher.matches("192.168.255.255".parse().unwrap()));
        assert!(!matcher.matches("192.169.0.1".parse().unwrap()));
    }

    #[test]
    fn test_is_empty() {
        let empty_matcher = IpMatcher::new(vec![]);
        assert!(empty_matcher.is_empty());

        let non_empty_matcher = IpMatcher::new(vec![
            "192.168.1.1".to_string(),
        ]);
        assert!(!non_empty_matcher.is_empty());
    }

    #[test]
    fn test_invalid_patterns() {
        // 这些无效的模式应该被忽略，不会导致 panic
        let matcher = IpMatcher::new(vec![
            "invalid".to_string(),
            "192.168.1.1.1".to_string(),
            "192.168.1.0/33".to_string(), // 无效的 IPv4 前缀长度
            "2001:db8::/129".to_string(), // 无效的 IPv6 前缀长度
            "".to_string(),
        ]);

        // 无效的模式被忽略，所以匹配器应该是空的
        assert!(matcher.is_empty());
    }

    #[test]
    fn test_cidr_single_host() {
        // /32 对于 IPv4 表示单个主机
        let matcher = IpMatcher::new(vec![
            "192.168.1.1/32".to_string(),
        ]);

        assert!(matcher.matches("192.168.1.1".parse().unwrap()));
        assert!(!matcher.matches("192.168.1.2".parse().unwrap()));

        // /128 对于 IPv6 表示单个主机
        let matcher_v6 = IpMatcher::new(vec![
            "2001:db8::1/128".to_string(),
        ]);

        assert!(matcher_v6.matches("2001:db8::1".parse().unwrap()));
        assert!(!matcher_v6.matches("2001:db8::2".parse().unwrap()));
    }

    #[test]
    fn test_cidr_all() {
        // 0.0.0.0/0 匹配所有 IPv4 地址
        let matcher_v4 = IpMatcher::new(vec![
            "0.0.0.0/0".to_string(),
        ]);

        assert!(matcher_v4.matches("192.168.1.1".parse().unwrap()));
        assert!(matcher_v4.matches("8.8.8.8".parse().unwrap()));
        assert!(matcher_v4.matches("255.255.255.255".parse().unwrap()));

        // ::/0 匹配所有 IPv6 地址
        let matcher_v6 = IpMatcher::new(vec![
            "::/0".to_string(),
        ]);

        assert!(matcher_v6.matches("::1".parse().unwrap()));
        assert!(matcher_v6.matches("2001:db8::1".parse().unwrap()));
        assert!(matcher_v6.matches("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap()));
    }
}
