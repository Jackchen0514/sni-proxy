use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sni_proxy::{SniProxy, Socks5Config};
use std::fs;
use std::net::SocketAddr;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    listen_addr: String,
    whitelist: Vec<String>,
    /// SOCKS5 代理配置（可选）
    socks5: Option<Socks5ConfigFile>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct Socks5ConfigFile {
    /// SOCKS5 代理服务器地址，格式：ip:port 或 domain:port
    addr: String,
    /// 用户名（可选）
    username: Option<String>,
    /// 密码（可选）
    password: Option<String>,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 64)]
async fn main() -> Result<()> {
    // 初始化日志
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    log::info!("Tokio 运行时配置: 64 工作线程 (确保 accept loop 能被及时调度)");

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

    // 创建代理实例
    let mut proxy = SniProxy::new(listen_addr, config.whitelist);

    // 配置 SOCKS5（如果提供）
    if let Some(socks5_config_file) = config.socks5 {
        log::info!("配置 SOCKS5 代理");

        // 解析 SOCKS5 地址
        let socks5_addr: SocketAddr = socks5_config_file
            .addr
            .parse()
            .context("无效的 SOCKS5 代理地址")?;

        log::info!("SOCKS5 代理服务器: {}", socks5_addr);

        if socks5_config_file.username.is_some() {
            log::info!("SOCKS5 认证方式: 用户名/密码");
        } else {
            log::info!("SOCKS5 认证方式: 无认证");
        }

        let socks5_config = Socks5Config {
            addr: socks5_addr,
            username: socks5_config_file.username,
            password: socks5_config_file.password,
        };

        proxy = proxy.with_socks5(socks5_config);
    } else {
        log::info!("未配置 SOCKS5，使用直接连接");
    }

    // 启动代理
    proxy.run().await?;

    Ok(())
}