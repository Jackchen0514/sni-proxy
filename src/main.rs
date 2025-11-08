use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sni_proxy::SniProxy;
use std::fs;
use std::net::SocketAddr;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    listen_addr: String,
    whitelist: Vec<String>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // 初始化日志
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    // 读取配置文件路径（命令行参数或默认值）
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.json".to_string());

    log::info!("读取配置文件: {}", config_path);

    // 读取并解析配置文件
    let config_content = fs::read_to_string(&config_path)
        .context(format!("无法读取配置文件: {}", config_path))?;

    let config: Config = serde_json::from_str(&config_content)
        .context("解析配置文件失败")?;

    let listen_addr: SocketAddr = config
        .listen_addr
        .parse()
        .context("无效的监听地址")?;

    log::info!("监听地址: {}", listen_addr);
    log::info!("加载了 {} 个白名单域名", config.whitelist.len());

    for (i, domain) in config.whitelist.iter().enumerate() {
        log::info!("  [{}] {}", i + 1, domain);
    }

    // 创建并启动代理
    let proxy = SniProxy::new(listen_addr, config.whitelist);
    proxy.run().await?;

    Ok(())
}