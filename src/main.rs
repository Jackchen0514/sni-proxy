use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use sni_proxy::logger::{init_logger, LogConfig, LogLevel};
use sni_proxy::{SniProxy, Socks5Config};
use std::fs;
use std::net::SocketAddr;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    listen_addr: String,
    /// 直连白名单
    whitelist: Vec<String>,
    /// SOCKS5 白名单（可选）
    #[serde(default)]
    socks5_whitelist: Vec<String>,
    /// IP 白名单（可选）
    /// 支持单个 IP 地址（如 "192.168.1.1"）或 CIDR 网段（如 "192.168.1.0/24"）
    /// 如果为空，则不进行 IP 白名单检查
    #[serde(default)]
    ip_whitelist: Vec<String>,
    /// IP 流量追踪配置（可选）
    ip_traffic_tracking: Option<IpTrafficTrackingConfig>,
    /// SOCKS5 代理配置（可选）
    socks5: Option<Socks5ConfigFile>,
    /// 日志配置（可选）
    log: Option<LogConfigFile>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct IpTrafficTrackingConfig {
    /// 是否启用 IP 流量追踪（仅对 IP 白名单中的 IP）
    #[serde(default)]
    enabled: bool,
    /// 最大跟踪的 IP 数量（使用 LRU 缓存）
    #[serde(default = "default_max_tracked_ips")]
    max_tracked_ips: usize,
    /// 统计数据输出文件路径（可选，每次覆盖写入最新数据）
    output_file: Option<String>,
    /// 持久化数据文件路径（可选，用于服务重启后恢复数据）
    persistence_file: Option<String>,
}

fn default_max_tracked_ips() -> usize {
    1000
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

    // 显示直连白名单
    log::info!("加载了 {} 个直连白名单域名", config.whitelist.len());
    for (i, domain) in config.whitelist.iter().take(10).enumerate() {
        log::info!("  [直连 {}] {}", i + 1, domain);
    }
    if config.whitelist.len() > 10 {
        log::info!("  ... 还有 {} 个直连域名", config.whitelist.len() - 10);
    }

    // 显示 SOCKS5 白名单
    if !config.socks5_whitelist.is_empty() {
        log::info!("加载了 {} 个 SOCKS5 白名单域名", config.socks5_whitelist.len());
        for (i, domain) in config.socks5_whitelist.iter().take(10).enumerate() {
            log::info!("  [SOCKS5 {}] {}", i + 1, domain);
        }
        if config.socks5_whitelist.len() > 10 {
            log::info!("  ... 还有 {} 个 SOCKS5 域名", config.socks5_whitelist.len() - 10);
        }
    }

    // 显示 IP 白名单
    if !config.ip_whitelist.is_empty() {
        log::info!("加载了 {} 个 IP 白名单规则", config.ip_whitelist.len());
        for (i, ip_pattern) in config.ip_whitelist.iter().take(10).enumerate() {
            log::info!("  [IP {}] {}", i + 1, ip_pattern);
        }
        if config.ip_whitelist.len() > 10 {
            log::info!("  ... 还有 {} 个 IP 规则", config.ip_whitelist.len() - 10);
        }
    } else {
        log::info!("未配置 IP 白名单，允许所有 IP 访问");
    }

    // 创建代理实例
    let has_socks5_whitelist = !config.socks5_whitelist.is_empty();
    let mut proxy = if has_socks5_whitelist {
        // 使用双白名单模式
        SniProxy::new_with_dual_whitelist(
            listen_addr,
            config.whitelist,
            config.socks5_whitelist,
        )
    } else {
        // 使用单一白名单模式（仅直连）
        SniProxy::new(listen_addr, config.whitelist)
    };

    // 配置 IP 白名单（如果提供）
    if !config.ip_whitelist.is_empty() {
        proxy = proxy.with_ip_whitelist(config.ip_whitelist);
    }

    // 配置 IP 流量追踪（如果启用且有 IP 白名单）
    if let Some(tracking_config) = config.ip_traffic_tracking {
        if tracking_config.enabled {
            log::info!("配置 IP 流量追踪");
            log::info!("  最大跟踪 IP 数量: {}", tracking_config.max_tracked_ips);
            if let Some(ref output_file) = tracking_config.output_file {
                log::info!("  统计数据输出文件: {}", output_file);
            }
            if let Some(ref persistence_file) = tracking_config.persistence_file {
                log::info!("  持久化数据文件: {}", persistence_file);
            }
            proxy = proxy.with_ip_traffic_tracking(
                tracking_config.max_tracked_ips,
                tracking_config.output_file,
                tracking_config.persistence_file,
            );
        }
    }

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
    } else if has_socks5_whitelist {
        log::warn!("配置了 SOCKS5 白名单但未配置 SOCKS5 代理服务器！");
        log::warn!("SOCKS5 白名单将无法生效，请检查配置文件");
    } else {
        log::info!("未配置 SOCKS5，所有流量使用直接连接");
    }

    log::info!("=== 服务器准备就绪 ===");

    // 启动代理
    proxy.run().await?;

    Ok(())
}
