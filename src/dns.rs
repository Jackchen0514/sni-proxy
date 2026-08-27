use anyhow::Result;
use lazy_static::lazy_static;
use log::{debug, info};
use lru::LruCache;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
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

/// 单个缓存分片
struct DnsCacheShard {
    cache: Mutex<LruCache<String, DnsCacheEntry>>,
}

lazy_static! {
    // 🚀 DNS 缓存分片：避免所有连接竞争同一把全局锁
    //
    // 之前是单个 `Mutex<LruCache>`，高并发下所有 worker 线程的每次查询/写入
    // 都要抢同一把锁，是延迟抖动的一个来源。这里按 host 哈希分散到多个分片，
    // 各分片独立加锁，把锁粒度从"全局"降到"1/N"。
    //
    // 分片数随 CPU 核心数自适应（4~32 之间取 2 的幂，方便用位运算取模），
    // 总缓存容量维持原来的自适应策略不变，只是均分到各分片。
    static ref DNS_CACHE: Vec<DnsCacheShard> = {
        // .max(1) 防止极端环境下 num_cpus 返回 0 导致 panic
        let num_cpus = num_cpus::get().max(1);
        let total_cache_size = if num_cpus <= 2 {
            500
        } else if num_cpus <= 8 {
            1000
        } else {
            2000
        };
        let shard_count = num_cpus.next_power_of_two().clamp(4, 32);
        let per_shard_size = (total_cache_size / shard_count).max(16);

        info!(
            "DNS 缓存初始化: {} 个分片 x {} 条 (总计约 {} 条)",
            shard_count, per_shard_size, shard_count * per_shard_size
        );

        (0..shard_count)
            .map(|_| DnsCacheShard {
                cache: Mutex::new(LruCache::new(NonZeroUsize::new(per_shard_size).unwrap())),
            })
            .collect()
    };
}

/// 根据 host 选择对应的缓存分片
fn shard_for(host: &str) -> &'static DnsCacheShard {
    let mut hasher = DefaultHasher::new();
    host.hash(&mut hasher);
    let idx = (hasher.finish() as usize) % DNS_CACHE.len();
    &DNS_CACHE[idx]
}

/// 带缓存的 DNS 解析（含 TTL 过期检查）
pub async fn resolve_host_cached(host: &str) -> Result<Vec<IpAddr>> {
    let shard = shard_for(host);

    // 1. 检查缓存（含 TTL 过期检查）
    {
        let mut cache = shard.cache.lock().await;
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
        let mut cache = shard.cache.lock().await;
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
    for shard in DNS_CACHE.iter() {
        shard.cache.lock().await.clear();
    }
    info!("DNS 缓存已清除");
}

/// 获取缓存条目数（用于监控）
pub async fn get_dns_cache_size() -> usize {
    let mut total = 0;
    for shard in DNS_CACHE.iter() {
        total += shard.cache.lock().await.len();
    }
    total
}
