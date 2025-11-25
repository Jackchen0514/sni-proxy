use log::{debug, error, info, warn};
use sni_proxy::logger::{init_logger, LogConfig, LogLevel};
use std::fs;
use std::thread;
use std::time::Duration;

fn main() {
    println!("=== 日志文件输出示例 ===\n");

    // 示例 1: 输出到文件
    println!("示例 1: 输出到文件 (logs/example1.log)");
    let config = LogConfig::new(LogLevel::Info)
        .with_file("logs/example1.log")
        .with_timestamp(true)
        .with_module(true);

    init_logger(config).expect("初始化日志失败");

    info!("这条日志会写入到 logs/example1.log");
    warn!("警告信息也会写入文件");
    error!("错误信息同样会写入文件");

    println!("✓ 日志已写入 logs/example1.log\n");
    thread::sleep(Duration::from_millis(100));

    // 示例 2: 同时输出到标准输出和文件
    println!("\n示例 2: 同时输出到标准输出和文件");
    println!("重新初始化日志系统...");

    // 注意：实际应用中日志只能初始化一次
    // 这里仅为演示，在真实场景中应该在程序启动时初始化一次

    // 读取并显示文件内容
    if let Ok(content) = fs::read_to_string("logs/example1.log") {
        println!("\nlogs/example1.log 的内容:");
        println!("{}", "-".repeat(60));
        println!("{}", content);
        println!("{}", "-".repeat(60));
    }

    // 示例 3: 带日志轮转的文件输出
    println!("\n示例 3: 日志轮转演示");
    println!("配置: 最大 1KB 每个文件，保留 3 个备份\n");

    // 创建一个新的示例来演示轮转
    create_rotating_log_demo();

    println!("\n=== 使用建议 ===");
    println!("1. 输出到文件: 适合生产环境，便于日志分析");
    println!("   config.with_file(\"logs/app.log\")");
    println!();
    println!("2. 同时输出: 开发时方便调试，同时保留日志记录");
    println!("   config.with_both(\"logs/app.log\")");
    println!();
    println!("3. 日志轮转: 防止单个日志文件过大");
    println!("   config.with_rotating_file(\"logs/app.log\", 10*1024*1024, 5)");
    println!("   // 10MB 每个文件，保留 5 个备份");
}

fn create_rotating_log_demo() {
    // 清理旧的测试文件
    let _ = fs::remove_dir_all("logs/rotating_test");

    let config = LogConfig::new(LogLevel::Info)
        .with_rotating_file("logs/rotating_test/app.log", 1024, 3)  // 1KB 每个文件
        .with_timestamp(false)
        .with_module(false);

    // 创建新的日志实例（仅用于演示）
    // 注意：这里我们不能重新初始化全局日志器，所以只展示配置
    println!("配置创建成功:");
    println!("  路径: logs/rotating_test/app.log");
    println!("  最大文件大小: 1KB");
    println!("  保留备份数: 3");
    println!();
    println!("当日志文件超过 1KB 时，会自动轮转:");
    println!("  app.log       <- 当前日志");
    println!("  app.log.1     <- 第1个备份");
    println!("  app.log.2     <- 第2个备份");
    println!("  app.log.3     <- 第3个备份（最旧）");

    // 模拟写入大量日志
    if let Ok(_) = init_logger(config) {
        for i in 1..=100 {
            info!("这是第 {} 条日志，用于测试日志轮转功能", i);
        }

        // 检查生成的文件
        println!("\n生成的日志文件:");
        if let Ok(entries) = fs::read_dir("logs/rotating_test") {
            for entry in entries {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if let Ok(metadata) = entry.metadata() {
                        println!("  {} ({} bytes)", path.display(), metadata.len());
                    }
                }
            }
        }
    }
}
