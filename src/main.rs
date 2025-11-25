use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sni_proxy::logger::{init_logger, LogConfig, LogLevel};
use sni_proxy::{SniProxy, Socks5Config};
use std::fs;
use std::net::SocketAddr;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    listen_addr: String,
    whitelist: Vec<String>,
    /// SOCKS5 代理配置（可选）
    socks5: Option<Socks5ConfigFile>,
    /// 日志配置（可选）
    log: Option<LogConfigFile>,
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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct LogConfigFile {
    /// 日志级别: off, error, warn, info, debug, trace
    #[serde(default = "default_log_level")]
    level: String,
    /// 日志输出目标: stdout, file, both
    #[serde(default = "default_log_output")]
    output: String,
    /// 日志文件路径（当 output 为 file 或 both 时需要）
    file_path: Option<String>,
    /// 是否启用日志轮转
    #[serde(default)]
    enable_rotation: bool,
    /// 单个日志文件最大大小（MB）
    #[serde(default = "default_max_size_mb")]
    max_size_mb: u64,
    /// 保留的日志文件数量
    #[serde(default = "default_max_backups")]
    max_backups: usize,
    /// 是否显示时间戳
    #[serde(default = "default_true")]
    show_timestamp: bool,
    /// 是否显示模块路径
    #[serde(default = "default_true")]
    show_module: bool,
    /// 是否使用颜色输出
    #[serde(default = "default_true")]
    use_color: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_log_output() -> String {
    "stdout".to_string()
}

fn default_max_size_mb() -> u64 {
    100
}

fn default_max_backups() -> usize {
    5
}

fn default_true() -> bool {
    true
}

impl Default for LogConfigFile {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            output: default_log_output(),
            file_path: None,
            enable_rotation: false,
            max_size_mb: default_max_size_mb(),
            max_backups: default_max_backups(),
            show_timestamp: true,
            show_module: true,
            use_color: true,
        }
    }
}

#[tokio::main(flavor = "multi_thread", worker_threads = 16)]
async fn main() -> Result<()> {
    // 读取配置文件路径（命令行参数或默认值）
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.json".to_string());

    // 读取并解析配置文件
    let config_content = fs::read_to_string(&config_path)
        .context(format!("无法读取配置文件: {}", config_path))?;

    let config: Config = serde_json::from_str(&config_content)
        .context("解析配置文件失败")?;

    // 初始化日志系统
    let log_config_file = config.log.unwrap_or_default();

    // 解析日志级别
    let log_level = LogLevel::from_str(&log_config_file.level)
        .unwrap_or(LogLevel::Info);

    // 创建日志配置
    let mut log_config = LogConfig::new(log_level)
        .with_timestamp(log_config_file.show_timestamp)
        .with_module(log_config_file.show_module)
        .with_color(log_config_file.use_color);

    // 设置输出目标
    match log_config_file.output.as_str() {
        "file" => {
            let file_path = log_config_file.file_path
                .unwrap_or_else(|| "logs/sni-proxy.log".to_string());

            if log_config_file.enable_rotation {
                let max_size = log_config_file.max_size_mb * 1024 * 1024;
                log_config = log_config.with_rotating_file(
                    &file_path,
                    max_size,
                    log_config_file.max_backups,
                );
            } else {
                log_config = log_config.with_file(&file_path);
            }
        }
        "both" => {
            let file_path = log_config_file.file_path
                .unwrap_or_else(|| "logs/sni-proxy.log".to_string());

            if log_config_file.enable_rotation {
                let max_size = log_config_file.max_size_mb * 1024 * 1024;
                log_config = log_config.with_rotating_file(
                    &file_path,
                    max_size,
                    log_config_file.max_backups,
                );
            } else {
                log_config = log_config.with_both(&file_path);
            }
        }
        _ => {
            // 默认输出到 stdout
        }
    }

    // 初始化日志
    init_logger(log_config)
        .map_err(|e| anyhow::anyhow!("初始化日志系统失败: {}", e))?;

    log::info!("=== SNI 代理服务器启动 ===");
    log::info!("配置文件: {}", config_path);

    let listen_addr: SocketAddr = config
        .listen_addr
        .parse()
        .context("无效的监听地址")?;

    log::info!("监听地址: {}", listen_addr);
    log::info!("日志级别: {}", log_config_file.level);
    log::info!("日志输出: {}", log_config_file.output);

    if log_config_file.enable_rotation {
        log::info!("日志轮转: 启用 ({}MB per file, {} backups)",
                   log_config_file.max_size_mb,
                   log_config_file.max_backups);
    }

    log::info!("加载了 {} 个白名单域名", config.whitelist.len());

    // 只显示前 10 个域名，避免日志过长
    for (i, domain) in config.whitelist.iter().take(10).enumerate() {
        log::info!("  [{}] {}", i + 1, domain);
    }
    if config.whitelist.len() > 10 {
        log::info!("  ... 还有 {} 个域名", config.whitelist.len() - 10);
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

    log::info!("=== 服务器准备就绪 ===");

    // 启动代理
    proxy.run().await?;

    Ok(())
}
