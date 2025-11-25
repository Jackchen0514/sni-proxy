use log::{debug, error, info, trace, warn};
use sni_proxy::logger::{init_logger, LogConfig, LogLevel};

fn main() {
    // 示例 1: 使用默认配置
    println!("=== 示例 1: 默认配置 (INFO 级别) ===\n");
    init_logger(LogConfig::default());

    error!("这是一条错误日志");
    warn!("这是一条警告日志");
    info!("这是一条信息日志");
    debug!("这条调试日志不会显示（默认级别是 INFO）");
    trace!("这条追踪日志不会显示（默认级别是 INFO）");

    println!("\n=== 示例 2: DEBUG 级别配置 ===\n");
    // 注意：在实际应用中，日志只能初始化一次
    // 这里为了演示，我们展示如何配置不同级别

    // 示例 2: DEBUG 级别
    let config = LogConfig::new(LogLevel::Debug)
        .with_timestamp(true)
        .with_module(true)
        .with_color(true);

    println!("配置: {:?}\n", config);
    println!("使用此配置将显示 DEBUG 及以上级别的日志");

    println!("\n=== 示例 3: 自定义格式配置 ===\n");

    // 示例 3: 不显示时间戳和模块
    let config = LogConfig::new(LogLevel::Info)
        .with_timestamp(false)
        .with_module(false)
        .with_color(false);

    println!("配置: {:?}\n", config);
    println!("使用此配置将得到简洁的日志输出");

    println!("\n=== 示例 4: 从字符串解析日志级别 ===\n");

    let levels = vec!["error", "warn", "info", "debug", "trace", "off"];
    for level_str in levels {
        if let Some(level) = LogLevel::from_str(level_str) {
            println!("'{}' -> {:?}", level_str, level);
        }
    }

    println!("\n=== 日志级别说明 ===");
    println!("OFF   - 关闭所有日志");
    println!("ERROR - 仅显示错误");
    println!("WARN  - 显示警告和错误");
    println!("INFO  - 显示信息、警告和错误（默认）");
    println!("DEBUG - 显示调试、信息、警告和错误");
    println!("TRACE - 显示所有日志");
}
