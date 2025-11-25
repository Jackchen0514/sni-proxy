use chrono::Local;
use log::{LevelFilter, Log, Metadata, Record};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

/// 日志配置
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// 日志级别
    pub level: LogLevel,
    /// 是否显示时间戳
    pub show_timestamp: bool,
    /// 是否显示模块路径
    pub show_module: bool,
    /// 是否使用颜色输出（仅终端）
    pub use_color: bool,
    /// 日志输出目标
    pub output: LogOutput,
}

/// 日志输出目标
#[derive(Debug, Clone)]
pub enum LogOutput {
    /// 仅输出到标准输出
    Stdout,
    /// 仅输出到文件
    File(PathBuf),
    /// 同时输出到标准输出和文件
    Both(PathBuf),
    /// 带日志轮转的文件输出
    RotatingFile {
        /// 日志文件路径（不含扩展名）
        path: PathBuf,
        /// 单个文件最大大小（字节）
        max_size: u64,
        /// 保留的日志文件数量
        max_backups: usize,
    },
}

/// 日志级别
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    /// 关闭所有日志
    Off,
    /// 错误日志
    Error,
    /// 警告日志
    Warn,
    /// 信息日志
    Info,
    /// 调试日志
    Debug,
    /// 追踪日志
    Trace,
}

impl LogLevel {
    /// 转换为 log::LevelFilter
    pub fn to_level_filter(&self) -> LevelFilter {
        match self {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warn => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }

    /// 从字符串解析日志级别
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "off" => Some(LogLevel::Off),
            "error" => Some(LogLevel::Error),
            "warn" | "warning" => Some(LogLevel::Warn),
            "info" => Some(LogLevel::Info),
            "debug" => Some(LogLevel::Debug),
            "trace" => Some(LogLevel::Trace),
            _ => None,
        }
    }
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: LogLevel::Info,
            show_timestamp: true,
            show_module: true,
            use_color: true,
            output: LogOutput::Stdout,
        }
    }
}

impl LogConfig {
    /// 创建新的日志配置
    pub fn new(level: LogLevel) -> Self {
        Self {
            level,
            ..Default::default()
        }
    }

    /// 设置日志级别
    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.level = level;
        self
    }

    /// 设置是否显示时间戳
    pub fn with_timestamp(mut self, show: bool) -> Self {
        self.show_timestamp = show;
        self
    }

    /// 设置是否显示模块路径
    pub fn with_module(mut self, show: bool) -> Self {
        self.show_module = show;
        self
    }

    /// 设置是否使用颜色
    pub fn with_color(mut self, use_color: bool) -> Self {
        self.use_color = use_color;
        self
    }

    /// 设置输出到文件
    pub fn with_file<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.output = LogOutput::File(path.as_ref().to_path_buf());
        self
    }

    /// 设置同时输出到标准输出和文件
    pub fn with_both<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.output = LogOutput::Both(path.as_ref().to_path_buf());
        self
    }

    /// 设置带轮转的文件输出
    pub fn with_rotating_file<P: AsRef<Path>>(
        mut self,
        path: P,
        max_size: u64,
        max_backups: usize,
    ) -> Self {
        self.output = LogOutput::RotatingFile {
            path: path.as_ref().to_path_buf(),
            max_size,
            max_backups,
        };
        self
    }
}

/// 自定义日志器
struct CustomLogger {
    config: LogConfig,
    file_writer: Option<Arc<Mutex<FileWriter>>>,
}

/// 文件写入器
struct FileWriter {
    file: File,
    current_size: u64,
    path: PathBuf,
    max_size: Option<u64>,
    max_backups: Option<usize>,
}

impl FileWriter {
    fn new(path: PathBuf, max_size: Option<u64>, max_backups: Option<usize>) -> io::Result<Self> {
        // 创建目录（如果不存在）
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        let current_size = file.metadata()?.len();

        Ok(Self {
            file,
            current_size,
            path,
            max_size,
            max_backups,
        })
    }

    fn write(&mut self, data: &str) -> io::Result<()> {
        let bytes = data.as_bytes();

        // 检查是否需要轮转
        if let Some(max_size) = self.max_size {
            if self.current_size + bytes.len() as u64 > max_size {
                self.rotate()?;
            }
        }

        self.file.write_all(bytes)?;
        self.file.flush()?;
        self.current_size += bytes.len() as u64;
        Ok(())
    }

    fn rotate(&mut self) -> io::Result<()> {
        // 刷新并关闭当前文件
        self.file.flush()?;

        // 轮转文件
        if let Some(max_backups) = self.max_backups {
            // 删除最旧的备份
            let oldest = self.path.with_extension(format!("log.{}", max_backups));
            let _ = std::fs::remove_file(oldest);

            // 重命名现有备份
            for i in (1..max_backups).rev() {
                let old_name = self.path.with_extension(format!("log.{}", i));
                let new_name = self.path.with_extension(format!("log.{}", i + 1));
                if old_name.exists() {
                    let _ = std::fs::rename(old_name, new_name);
                }
            }

            // 重命名当前文件
            let backup = self.path.with_extension("log.1");
            std::fs::rename(&self.path, backup)?;
        }

        // 创建新文件
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.current_size = 0;

        Ok(())
    }
}

impl Log for CustomLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.config.level.to_level_filter()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let formatted = self.format_log(record, false);
        let formatted_color = self.format_log(record, true);

        // 输出到标准输出
        match &self.config.output {
            LogOutput::Stdout | LogOutput::Both(_) => {
                if self.config.use_color {
                    println!("{}", formatted_color);
                } else {
                    println!("{}", formatted);
                }
            }
            _ => {}
        }

        // 输出到文件（文件中不使用颜色）
        if let Some(writer) = &self.file_writer {
            if let Ok(mut w) = writer.lock() {
                let _ = w.write(&format!("{}\n", formatted));
            }
        }
    }

    fn flush(&self) {
        if let Some(writer) = &self.file_writer {
            if let Ok(mut w) = writer.lock() {
                let _ = w.file.flush();
            }
        }
    }
}

impl CustomLogger {
    fn format_log(&self, record: &Record, use_color: bool) -> String {
        // 时间戳
        let timestamp = if self.config.show_timestamp {
            format!("[{}] ", Local::now().format("%Y-%m-%d %H:%M:%S%.3f"))
        } else {
            String::new()
        };

        // 日志级别
        let level = if use_color && self.config.use_color {
            match record.level() {
                log::Level::Error => "\x1b[31mERROR\x1b[0m", // 红色
                log::Level::Warn => "\x1b[33mWARN \x1b[0m",  // 黄色
                log::Level::Info => "\x1b[32mINFO \x1b[0m",  // 绿色
                log::Level::Debug => "\x1b[36mDEBUG\x1b[0m", // 青色
                log::Level::Trace => "\x1b[35mTRACE\x1b[0m", // 紫色
            }
        } else {
            match record.level() {
                log::Level::Error => "ERROR",
                log::Level::Warn => "WARN ",
                log::Level::Info => "INFO ",
                log::Level::Debug => "DEBUG",
                log::Level::Trace => "TRACE",
            }
        };

        // 模块路径
        let module = if self.config.show_module {
            if let Some(module_path) = record.module_path() {
                format!("[{}] ", module_path)
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        format!("{}{} {} {}", timestamp, level, module, record.args())
    }
}

/// 初始化日志系统
///
/// # 示例
///
/// ```no_run
/// use sni_proxy::logger::{init_logger, LogConfig, LogLevel};
///
/// // 使用默认配置（输出到标准输出）
/// init_logger(LogConfig::default()).unwrap();
///
/// // 输出到文件
/// let config = LogConfig::new(LogLevel::Info)
///     .with_file("logs/app.log");
/// init_logger(config).unwrap();
///
/// // 同时输出到标准输出和文件
/// let config = LogConfig::new(LogLevel::Debug)
///     .with_both("logs/app.log");
/// init_logger(config).unwrap();
///
/// // 带日志轮转（10MB 每个文件，保留 5 个备份）
/// let config = LogConfig::new(LogLevel::Info)
///     .with_rotating_file("logs/app.log", 10 * 1024 * 1024, 5);
/// init_logger(config).unwrap();
/// ```
pub fn init_logger(config: LogConfig) -> Result<(), String> {
    let file_writer = match &config.output {
        LogOutput::File(path) | LogOutput::Both(path) => {
            let writer = FileWriter::new(path.clone(), None, None)
                .map_err(|e| format!("无法创建日志文件: {}", e))?;
            Some(Arc::new(Mutex::new(writer)))
        }
        LogOutput::RotatingFile {
            path,
            max_size,
            max_backups,
        } => {
            let writer = FileWriter::new(path.clone(), Some(*max_size), Some(*max_backups))
                .map_err(|e| format!("无法创建日志文件: {}", e))?;
            Some(Arc::new(Mutex::new(writer)))
        }
        LogOutput::Stdout => None,
    };

    let logger = CustomLogger {
        config,
        file_writer,
    };

    log::set_boxed_logger(Box::new(logger))
        .map_err(|e| format!("设置日志器失败: {}", e))?;
    log::set_max_level(LevelFilter::Trace);

    Ok(())
}

/// 使用默认配置初始化日志系统
///
/// 等同于 `init_logger(LogConfig::default())`
pub fn init_default_logger() -> Result<(), String> {
    init_logger(LogConfig::default())
}

/// 从环境变量初始化日志系统
///
/// 读取 RUST_LOG 环境变量来设置日志级别
///
/// # 示例
///
/// ```bash
/// RUST_LOG=debug ./sni-proxy
/// RUST_LOG=info ./sni-proxy
/// ```
pub fn init_from_env() -> Result<(), String> {
    let level_str = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    let level = LogLevel::from_str(&level_str).unwrap_or(LogLevel::Info);
    init_logger(LogConfig::new(level))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_from_str() {
        assert_eq!(LogLevel::from_str("error"), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_str("ERROR"), Some(LogLevel::Error));
        assert_eq!(LogLevel::from_str("warn"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::from_str("info"), Some(LogLevel::Info));
        assert_eq!(LogLevel::from_str("debug"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::from_str("trace"), Some(LogLevel::Trace));
        assert_eq!(LogLevel::from_str("off"), Some(LogLevel::Off));
        assert_eq!(LogLevel::from_str("invalid"), None);
    }

    #[test]
    fn test_log_level_to_level_filter() {
        assert_eq!(LogLevel::Off.to_level_filter(), LevelFilter::Off);
        assert_eq!(LogLevel::Error.to_level_filter(), LevelFilter::Error);
        assert_eq!(LogLevel::Warn.to_level_filter(), LevelFilter::Warn);
        assert_eq!(LogLevel::Info.to_level_filter(), LevelFilter::Info);
        assert_eq!(LogLevel::Debug.to_level_filter(), LevelFilter::Debug);
        assert_eq!(LogLevel::Trace.to_level_filter(), LevelFilter::Trace);
    }

    #[test]
    fn test_log_config_default() {
        let config = LogConfig::default();
        assert_eq!(config.level, LogLevel::Info);
        assert!(config.show_timestamp);
        assert!(config.show_module);
        assert!(config.use_color);
    }

    #[test]
    fn test_log_config_builder() {
        let config = LogConfig::new(LogLevel::Debug)
            .with_timestamp(false)
            .with_module(false)
            .with_color(false);

        assert_eq!(config.level, LogLevel::Debug);
        assert!(!config.show_timestamp);
        assert!(!config.show_module);
        assert!(!config.use_color);
    }

    #[test]
    fn test_log_config_with_file() {
        let config = LogConfig::new(LogLevel::Info).with_file("test.log");
        assert!(matches!(config.output, LogOutput::File(_)));
    }

    #[test]
    fn test_log_config_with_rotating_file() {
        let config = LogConfig::new(LogLevel::Info)
            .with_rotating_file("test.log", 1024 * 1024, 5);
        assert!(matches!(config.output, LogOutput::RotatingFile { .. }));
    }
}
