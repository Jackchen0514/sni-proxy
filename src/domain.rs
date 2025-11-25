use log::info;
use std::collections::HashSet;

/// 域名匹配器，支持精确匹配和通配符匹配
#[derive(Debug, Clone)]
pub struct DomainMatcher {
    /// 精确匹配的域名列表
    exact_domains: HashSet<String>,
    /// 通配符域名列表（例如 "*.example.com"），已排序以优化匹配
    wildcard_domains: Vec<String>,
}

impl DomainMatcher {
    /// 创建新的域名匹配器
    pub fn new(domains: Vec<String>) -> Self {
        let mut exact_domains = HashSet::new();
        let mut wildcard_domains = Vec::new();

        for domain in domains {
            let domain_lower = domain.to_lowercase(); // 统一转换为小写

            if domain_lower.starts_with("*.") {
                // 通配符域名
                let suffix = domain_lower[2..].to_string();
                if !suffix.is_empty() {
                    wildcard_domains.push(suffix);
                    info!("添加通配符域名: {}", domain_lower);
                }
            } else if !domain_lower.is_empty() {
                // 精确匹配域名
                exact_domains.insert(domain_lower.clone());
                info!("添加精确匹配域名: {}", domain_lower);
            }
        }

        // 按长度排序通配符域名（更长的优先匹配，提高准确性）
        wildcard_domains.sort_by(|a, b| b.len().cmp(&a.len()));

        Self {
            exact_domains,
            wildcard_domains,
        }
    }

    /// 检查域名是否匹配白名单
    #[inline]
    pub fn matches(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        // 先检查精确匹配（O(1)）
        if self.exact_domains.contains(&domain_lower) {
            return true;
        }

        // 再检查通配符匹配（O(n)，但已优化）
        for wildcard_suffix in &self.wildcard_domains {
            if domain_lower.len() > wildcard_suffix.len()
                && domain_lower.ends_with(wildcard_suffix) {
                // 确保匹配的是完整的子域名
                let prefix_len = domain_lower.len() - wildcard_suffix.len();
                if &domain_lower[prefix_len - 1..prefix_len] == "." {
                    return true;
                }
            }
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_matcher_exact() {
        let matcher = DomainMatcher::new(vec![
            "example.com".to_string(),
            "github.com".to_string(),
        ]);

        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("EXAMPLE.COM")); // 大小写不敏感
        assert!(matcher.matches("github.com"));
        assert!(!matcher.matches("www.example.com"));
        assert!(!matcher.matches("notexample.com"));
    }

    #[test]
    fn test_domain_matcher_wildcard() {
        let matcher = DomainMatcher::new(vec![
            "*.example.com".to_string(),
            "github.com".to_string(),
        ]);

        // 通配符应该匹配子域名
        assert!(matcher.matches("www.example.com"));
        assert!(matcher.matches("api.example.com"));
        assert!(matcher.matches("test.api.example.com"));
        assert!(matcher.matches("WWW.EXAMPLE.COM")); // 大小写不敏感

        // 精确匹配
        assert!(matcher.matches("github.com"));
        assert!(matcher.matches("GITHUB.COM")); // 大小写不敏感

        // 不应该匹配
        assert!(!matcher.matches("example.com")); // 通配符不匹配主域名本身
        assert!(!matcher.matches("notexample.com"));
        assert!(!matcher.matches("www.github.com")); // github.com 是精确匹配
    }

    #[test]
    fn test_domain_matcher_mixed() {
        let matcher = DomainMatcher::new(vec![
            "example.com".to_string(),
            "*.example.com".to_string(),
            "*.api.example.com".to_string(),
            "github.com".to_string(),
        ]);

        // 精确匹配
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("github.com"));

        // 一级通配符
        assert!(matcher.matches("www.example.com"));
        assert!(matcher.matches("mail.example.com"));

        // 二级通配符
        assert!(matcher.matches("v1.api.example.com"));
        assert!(matcher.matches("v2.api.example.com"));

        // 不应该匹配
        assert!(!matcher.matches("www.github.com"));
        assert!(!matcher.matches("test.com"));
    }

    #[test]
    fn test_domain_matcher_edge_cases() {
        let matcher = DomainMatcher::new(vec![
            "*.example.com".to_string(),
        ]);

        // 边界情况测试
        assert!(!matcher.matches("example.com")); // 主域名不匹配
        assert!(!matcher.matches("notexample.com")); // 不是子域名
        assert!(!matcher.matches("testexample.com")); // 不是子域名
        assert!(matcher.matches("a.example.com")); // 单字母子域名
        assert!(matcher.matches("test.sub.example.com")); // 多级子域名
    }

    #[test]
    fn test_domain_matcher_case_insensitive() {
        let matcher = DomainMatcher::new(vec![
            "Example.Com".to_string(),
            "*.GitHub.IO".to_string(),
        ]);

        // 应该不区分大小写
        assert!(matcher.matches("example.com"));
        assert!(matcher.matches("EXAMPLE.COM"));
        assert!(matcher.matches("Example.Com"));
        assert!(matcher.matches("user.github.io"));
        assert!(matcher.matches("USER.GITHUB.IO"));
    }

    #[test]
    fn test_domain_matcher_empty() {
        let matcher = DomainMatcher::new(vec![]);

        assert!(!matcher.matches("example.com"));
        assert!(!matcher.matches("www.example.com"));
    }

    #[test]
    fn test_domain_matcher_wildcard_sorting() {
        // 测试通配符按长度排序（更具体的优先）
        let matcher = DomainMatcher::new(vec![
            "*.com".to_string(),
            "*.example.com".to_string(),
            "*.api.example.com".to_string(),
        ]);

        // 应该匹配最具体的规则
        assert!(matcher.matches("v1.api.example.com"));
        assert!(matcher.matches("www.example.com"));
        assert!(matcher.matches("test.com"));
    }
}
