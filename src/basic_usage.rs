// examples/basic_usage.rs
// 基本使用示例（支持 SOCKS5）

use anyhow::Result;
use sni_proxy::{SniProxy, Socks5Config};
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

    // 创建代理服务器
    let proxy = SniProxy::new(listen_addr, whitelist);

    // 示例 1: 不使用 SOCKS5，直接连接
    println!("=== 示例 1: 直接连接（无 SOCKS5）===\n");
    // 运行代理
    // proxy.run().await?;

    // 示例 2: 使用 SOCKS5 无认证
    println!("=== 示例 2: 使用 SOCKS5（无认证）===\n");
    let socks5_config = Socks5Config {
        addr: "127.0.0.1:1080".parse()?,
        username: None,
        password: None,
    };
    let proxy = proxy.with_socks5(socks5Config);
    println!("SOCKS5 代理: 127.0.0.1:1080");
    println!("认证方式: 无认证\n");
    // proxy.run().await?;

    // 示例 3: 使用 SOCKS5 有认证
    println!("=== 示例 3: 使用 SOCKS5（用户名/密码认证）===\n");
    let proxy = SniProxy::new(listen_addr, vec![
        "www.google.com".to_string(),
        "github.com".to_string(),
    ]);
    let socks5_config = Socks5Config {
        addr: "proxy.example.com:1080".parse()?,
        username: Some("myuser".to_string()),
        password: Some("mypassword".to_string()),
    };
    let proxy = proxy.with_socks5(socks5_config);
    println!("SOCKS5 代理: proxy.example.com:1080");
    println!("认证方式: 用户名/密码");
    println!("用户名: myuser");
    println!("密码: ****\n");

    // 运行代理服务器
    proxy.run().await?;

    Ok(())
}