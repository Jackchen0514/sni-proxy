use anyhow::Result;
use lazy_static::lazy_static;
use log::{debug, info};
use lru::LruCache;
use std::net::IpAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// DNS 缓存 TTL：5 分钟后过期重新解析
const DNS_CACHE_TTL: Duration = Duration::from_secs(300);

struct DnsCacheEntry {
    ips: Vec<IpAddr>,
    expires_at: Instant,
}

lazy_static! {
    // 🚀 自适应 DNS 缓存大小：根据 CPU 核心数调整
    // 小型服务器（1-2核）：500 条
    // 中型服务器（4-8核）：1000 条
    // 大型服务器（16+核）：2000 条
    static ref DNS_CACHE: Mutex<LruCache<String, DnsCacheEntry>> = {
        // .max(1) 防止极端环境下 num_cpus 返回 0 导致 panic
        let num_cpus = num_cpus::get().max(1);
        let cache_size = if num_cpus <= 2 {
            500
        } else if num_cpus <= 8 {
            1000
        } else {
            2000
        };
        Mutex::new(LruCache::new(NonZeroUsize::new(cache_size).unwrap()))
    };
}

/// 带缓存的 DNS 解析（含 TTL 过期检查）
pub async fn resolve_host_cached(host: &str) -> Result<Vec<IpAddr>> {
    // 1. 检查缓存（含 TTL 过期检查）
    {
        let mut cache = DNS_CACHE.lock().await;
        if let Some(entry) = cache.get(host) {
            if entry.expires_at > Instant::now() {
                debug!("DNS 缓存命中: {} -> {:?}", host, entry.ips);
                return Ok(entry.ips.clone());
            }
        }
        // 条目过期或不存在，移除（pop 对不存在的条目是空操作）
        cache.pop(host);
        debug!("DNS 缓存过期或未命中，重新查询: {}", host);
    }

    // 2. 执行 DNS 查询
    debug!("DNS 查询: {}", host);
    let addr_str = format!("{}:443", host);
    let ips: Vec<IpAddr> = tokio::net::lookup_host(&addr_str)
        .await?
        .map(|addr| addr.ip())
        .collect();

    if ips.is_empty() {
        return Err(anyhow::anyhow!("DNS 查询返回空列表: {}", host));
    }

    // 3. 缓存结果，写入 TTL
    {
        let mut cache = DNS_CACHE.lock().await;
        cache.put(
            host.to_string(),
            DnsCacheEntry {
                ips: ips.clone(),
                expires_at: Instant::now() + DNS_CACHE_TTL,
            },
        );
        debug!("DNS 缓存写入: {} -> {:?}", host, ips);
    }

    Ok(ips)
}

/// 清除 DNS 缓存
pub async fn clear_dns_cache() {
    let mut cache = DNS_CACHE.lock().await;
    cache.clear();
    info!("DNS 缓存已清除");
}

/// 获取缓存条目数（用于监控）
pub async fn get_dns_cache_size() -> usize {
    let cache = DNS_CACHE.lock().await;
    cache.len()
}
