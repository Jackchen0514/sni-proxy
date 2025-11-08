// examples/basic_usage.rs
// 基本使用示例

use anyhow::Result;
use sni_proxy::SniProxy;
use std::net::SocketAddr;

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志系统
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info")
    ).init();

    // 设置监听地址
    let listen_addr: SocketAddr = "127.0.0.1:8443".parse()?;

    // 定义白名单域名列表
    let whitelist = vec![
        // 允许访问的域名
        "www.google.com".to_string(),
        "github.com".to_string(),
        "www.rust-lang.org".to_string(),
        "docs.rs".to_string(),
        "crates.io".to_string(),
    ];

    println!("🚀 启动 SNI 代理服务器");
    println!("📍 监听地址: {}", listen_addr);
    println!("📋 白名单域名数量: {}", whitelist.len());
    println!("✅ 允许的域名:");
    for domain in &whitelist {
        println!("   - {}", domain);
    }
    println!("\n按 Ctrl+C 停止服务器\n");

    // 创建并运行代理服务器
    let proxy = SniProxy::new(listen_addr, whitelist);
    proxy.run().await?;

    Ok(())
}
