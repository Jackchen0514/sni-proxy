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
    /// 域名-IP 追踪配置（可选）
    domain_ip_tracking: Option<DomainIpTrackingConfig>,
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
struct DomainIpTrackingConfig {
    /// 是否启用域名-IP 追踪
    #[serde(default)]
    enabled: bool,
    /// 输出文件路径
    output_file: Option<String>,
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

/// 验证配置的有效性
fn validate_config(config: &Config) -> Result<()> {
    // 验证监听地址
    config
        .listen_addr
        .parse::<SocketAddr>()
        .context("无效的监听地址格式")?;

    // 验证白名单不能为空
    if config.whitelist.is_empty() && config.socks5_whitelist.is_empty() {
        anyhow::bail!("直连白名单和 SOCKS5 白名单不能同时为空");
    }

    // 验证 SOCKS5 配置
    if let Some(ref socks5) = config.socks5 {
        socks5
            .addr
            .parse::<SocketAddr>()
            .context("无效的 SOCKS5 代理地址格式")?;

        // 检查用户名和密码的一致性
        if socks5.username.is_some() != socks5.password.is_some() {
            anyhow::bail!("SOCKS5 用户名和密码必须同时提供或同时省略");
        }
    }

    // 验证 IP 流量追踪配置
    if let Some(ref tracking) = config.ip_traffic_tracking {
        if tracking.enabled {
            // 验证 max_tracked_ips 合理性
            if tracking.max_tracked_ips == 0 {
                anyhow::bail!("IP 流量追踪的 max_tracked_ips 必须大于 0");
            }
            if tracking.max_tracked_ips > 1_000_000 {
                log::warn!("⚠️  max_tracked_ips 设置过大 ({})，可能占用大量内存", tracking.max_tracked_ips);
            }

            // 验证输出文件路径可写
            if let Some(ref output_file) = tracking.output_file {
                if let Some(parent) = std::path::Path::new(output_file).parent() {
                    if !parent.exists() {
                        log::warn!("⚠️  输出文件目录不存在: {:?}，尝试创建...", parent);
                        std::fs::create_dir_all(parent)
                            .context(format!("无法创建输出文件目录: {:?}", parent))?;
                    }
                }
            }

            // 验证持久化文件路径可写
            if let Some(ref persistence_file) = tracking.persistence_file {
                if let Some(parent) = std::path::Path::new(persistence_file).parent() {
                    if !parent.exists() {
                        log::warn!("⚠️  持久化文件目录不存在: {:?}，尝试创建...", parent);
                        std::fs::create_dir_all(parent)
                            .context(format!("无法创建持久化文件目录: {:?}", parent))?;
                    }
                }
            }
        }
    }

    // 验证日志配置
    if let Some(ref log_config) = config.log {
        // 验证日志级别
        let valid_levels = ["off", "error", "warn", "info", "debug", "trace"];
        if !valid_levels.contains(&log_config.level.as_str()) {
            anyhow::bail!(
                "无效的日志级别: {}，有效值: {:?}",
                log_config.level,
                valid_levels
            );
        }

        // 验证日志输出
        let valid_outputs = ["stdout", "file", "both"];
        if !valid_outputs.contains(&log_config.output.as_str()) {
            anyhow::bail!(
                "无效的日志输出: {}，有效值: {:?}",
                log_config.output,
                valid_outputs
            );
        }

        // 如果输出到文件，验证文件路径
        if log_config.output == "file" || log_config.output == "both" {
            if log_config.file_path.is_none() {
                log::warn!("⚠️  日志输出到文件但未指定路径，将使用默认路径: logs/sni-proxy.log");
            } else if let Some(ref file_path) = log_config.file_path {
                if let Some(parent) = std::path::Path::new(file_path).parent() {
                    if !parent.exists() {
                        log::warn!("⚠️  日志文件目录不存在: {:?}，尝试创建...", parent);
                        std::fs::create_dir_all(parent)
                            .context(format!("无法创建日志文件目录: {:?}", parent))?;
                    }
                }
            }
        }

        // 验证日志轮转配置
        if log_config.enable_rotation {
            if log_config.max_size_mb == 0 {
                anyhow::bail!("启用日志轮转时，max_size_mb 必须大于 0");
            }
            if log_config.max_backups == 0 {
                log::warn!("⚠️  max_backups 为 0，日志文件将不保留备份");
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    // ⚡ 性能优化：自定义 Tokio 运行时配置
    // 小型服务器优化（<= 2核）：使用 CPU 核心数作为工作线程数
    // 大型服务器优化（> 2核）：使用 CPU 核心数的一半
    let num_cpus = num_cpus::get();
    let worker_threads = if num_cpus <= 2 {
        num_cpus  // 小型服务器：使用所有核心
    } else {
        std::cmp::max(4, num_cpus / 2)  // 大型服务器：使用一半
    };

    let runtime = tokio::runtime::Builder::new_multi_thread()
        // 工作线程数：根据 CPU 核心数自适应
        .worker_threads(worker_threads)
        // 线程命名：便于调试和监控
        .thread_name("sni-proxy-worker")
        // 使用默认栈大小（约 512KB-1MB，节省内存）
        // 启用所有 Tokio 功能（I/O、时间、信号等）
        .enable_all()
        // 全局队列间隔：31（默认值，平衡公平性和性能）
        .global_queue_interval(31)
        // 事件间隔：小型服务器使用 61 减少 CPU 开销
        .event_interval(if num_cpus <= 2 { 61 } else { 31 })
        .build()
        .context("创建 Tokio 运行时失败")?;

    // 在运行时中执行主逻辑
    runtime.block_on(async_main())
}

async fn async_main() -> Result<()> {
    // 读取配置文件路径（命令行参数或默认值）
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.json".to_string());

    // 读取并解析配置文件
    let config_content = fs::read_to_string(&config_path)
        .context(format!("无法读取配置文件: {}", config_path))?;

    let config: Config = serde_json::from_str(&config_content)
        .context("解析配置文件失败")?;

    // 验证配置
    validate_config(&config)
        .context("配置验证失败")?;

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

    // ⚡ 显示运行时配置
    let num_cpus = num_cpus::get();
    let num_physical_cpus = num_cpus::get_physical();
    let worker_threads = if num_cpus <= 2 {
        num_cpus
    } else {
        std::cmp::max(4, num_cpus / 2)
    };
    let event_interval = if num_cpus <= 2 { 61 } else { 31 };

    log::info!("🚀 Tokio 运行时配置:");
    log::info!("  CPU 核心: {} 物理, {} 逻辑", num_physical_cpus, num_cpus);
    log::info!("  工作线程数: {} ({})", worker_threads,
        if num_cpus <= 2 { "小型服务器模式" } else { "大型服务器模式" });
    log::info!("  线程栈大小: 默认 (~1MB)");
    log::info!("  全局队列间隔: 31");
    log::info!("  事件间隔: {} ({})", event_interval,
        if num_cpus <= 2 { "节省 CPU" } else { "I/O 优化" });

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
    if config.whitelist.contains(&"*".to_string()) {
        log::info!("直连白名单: 匹配所有域名（*）");
    } else {
        log::info!("加载了 {} 个直连白名单域名", config.whitelist.len());
        for (i, domain) in config.whitelist.iter().take(10).enumerate() {
            log::info!("  [直连 {}] {}", i + 1, domain);
        }
        if config.whitelist.len() > 10 {
            log::info!("  ... 还有 {} 个直连域名", config.whitelist.len() - 10);
        }
    }

    // 显示 SOCKS5 白名单
    if !config.socks5_whitelist.is_empty() {
        if config.socks5_whitelist.contains(&"*".to_string()) {
            log::info!("SOCKS5 白名单: 匹配所有域名（*）");
        } else {
            log::info!("加载了 {} 个 SOCKS5 白名单域名", config.socks5_whitelist.len());
            for (i, domain) in config.socks5_whitelist.iter().take(10).enumerate() {
                log::info!("  [SOCKS5 {}] {}", i + 1, domain);
            }
            if config.socks5_whitelist.len() > 10 {
                log::info!("  ... 还有 {} 个 SOCKS5 域名", config.socks5_whitelist.len() - 10);
            }
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

    // 配置域名-IP 追踪（如果启用）
    if let Some(domain_ip_tracking_config) = config.domain_ip_tracking {
        if domain_ip_tracking_config.enabled {
            log::info!("启用域名-IP 追踪:");
            if let Some(ref output_file) = domain_ip_tracking_config.output_file {
                log::info!("  输出文件: {}", output_file);
            } else {
                log::info!("  输出文件: 未指定（不保存到文件）");
            }
            proxy = proxy.with_domain_ip_tracking(domain_ip_tracking_config.output_file);
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

    // 创建优雅关闭信号通道
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // 启动信号监听任务
    tokio::spawn(async move {
        use tokio::signal;

        // 监听 SIGTERM (kill 默认信号)
        #[cfg(unix)]
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("创建 SIGTERM 信号监听失败");

        // 监听 SIGINT (Ctrl+C)
        let sigint = signal::ctrl_c();

        // 监听 SIGQUIT (Ctrl+\)
        #[cfg(unix)]
        let mut sigquit = signal::unix::signal(signal::unix::SignalKind::quit())
            .expect("创建 SIGQUIT 信号监听失败");

        #[cfg(unix)]
        tokio::select! {
            _ = sigterm.recv() => {
                log::info!("🛑 收到 SIGTERM 信号");
            }
            _ = sigint => {
                log::info!("🛑 收到 SIGINT (Ctrl+C) 信号");
            }
            _ = sigquit.recv() => {
                log::info!("🛑 收到 SIGQUIT (Ctrl+\\) 信号");
            }
        }

        #[cfg(not(unix))]
        {
            let _ = sigint.await;
            log::info!("🛑 收到 Ctrl+C 信号");
        }

        log::info!("🛑 正在优雅关闭服务器...");

        // 发送关闭信号
        if let Err(e) = shutdown_tx.send(true) {
            log::error!("发送关闭信号失败: {}", e);
        }
    });

    // 启动代理（支持优雅关闭）
    proxy.run_with_shutdown(Some(shutdown_rx)).await?;

    log::info!("=== 服务器已关闭 ===");

    Ok(())
}
