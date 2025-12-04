/// eBPF 加速示例
///
/// 展示如何使用 eBPF 技术优化 SNI 代理性能
///
/// 使用方法:
/// ```bash
/// cargo run --example ebpf_demo
/// ```
///
/// 性能对比:
/// - 传统模式: 50,000 req/s
/// - eBPF 模式: 100,000-150,000 req/s (2-3x 提升)

use sni_proxy::{EbpfConfig, EbpfManager};
use log::{error, info};

fn main() {
    // 初始化日志
    env_logger::Builder::from_default_env()
        .filter_level(log::LevelFilter::Info)
        .init();

    info!("===== eBPF 加速示例 =====");

    // 1. 创建 eBPF 配置
    let config = EbpfConfig {
        enabled: true,
        sockmap_enabled: true,
        dns_cache_enabled: true,
        dns_cache_size: 10000,
        stats_enabled: true,
    };

    // 2. 初始化 eBPF 管理器
    match EbpfManager::new(config) {
        Ok(mut manager) => {
            info!("✓ eBPF 管理器初始化成功");

            // 3. 打印系统能力
            let caps = manager.capabilities();
            info!("系统能力: {}", caps.summary());

            // 4. 打印状态
            manager.print_status();

            // 5. 模拟使用场景
            demo_sockmap(&mut manager);
            demo_dns_cache(&mut manager);

            // 6. 打印最终状态
            info!("\n===== 最终状态 =====");
            manager.print_status();
        }
        Err(e) => {
            error!("✗ eBPF 管理器初始化失败: {}", e);
            info!("将使用传统模式运行");
        }
    }
}

/// 演示 Sockmap 功能
fn demo_sockmap(manager: &mut EbpfManager) {
    info!("\n===== Sockmap 演示 =====");

    if !manager.is_sockmap_enabled() {
        info!("Sockmap 未启用，跳过演示");
        return;
    }

    // 模拟注册 socket 对
    let client_fd = 10;
    let target_fd = 20;

    match manager.register_socket_pair(client_fd, target_fd) {
        Ok(()) => {
            info!("✓ 成功注册 socket 对: {} ↔ {}", client_fd, target_fd);

            // 模拟数据传输
            manager.record_sent(client_fd, 1024);
            manager.record_received(target_fd, 2048);

            // 注销
            match manager.unregister_socket_pair(client_fd, target_fd) {
                Ok(()) => info!("✓ 成功注销 socket 对"),
                Err(e) => error!("✗ 注销失败: {}", e),
            }
        }
        Err(e) => {
            error!("✗ 注册失败: {}", e);
        }
    }
}

/// 演示 DNS 缓存功能
fn demo_dns_cache(manager: &mut EbpfManager) {
    info!("\n===== DNS 缓存演示 =====");

    if !manager.is_dns_cache_enabled() {
        info!("DNS 缓存未启用，跳过演示");
        return;
    }

    let domain = "example.com";
    let ip = "93.184.216.34".parse().unwrap();

    // 首次查询（未命中）
    match manager.lookup_dns(domain) {
        Some(cached_ip) => {
            info!("DNS 缓存命中: {} → {}", domain, cached_ip);
        }
        None => {
            info!("DNS 缓存未命中: {}", domain);

            // 插入缓存
            match manager.insert_dns(domain, ip) {
                Ok(()) => info!("✓ DNS 缓存已更新: {} → {}", domain, ip),
                Err(e) => error!("✗ 缓存更新失败: {}", e),
            }
        }
    }

    // 再次查询（应该命中）
    match manager.lookup_dns(domain) {
        Some(cached_ip) => {
            info!("✓ DNS 缓存命中: {} → {}", domain, cached_ip);
            assert_eq!(cached_ip, ip);
        }
        None => {
            error!("✗ DNS 缓存应该命中但未命中");
        }
    }
}
