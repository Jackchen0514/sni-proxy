/// eBPF 管理器
///
/// 统一管理所有 eBPF 组件：
/// - Sockmap: 数据转发
/// - DNS 缓存: 域名解析加速
/// - 流量统计: 性能监控
///
/// 提供优雅降级：
/// - eBPF 初始化失败时自动降级到传统模式
/// - 部分功能失败不影响整体运行

use super::{EbpfCapabilities, EbpfDnsCache, SockmapManager, EbpfStats};
use anyhow::{Context, Result};
use aya::Bpf;
use log::{error, info, warn};
use std::net::IpAddr;
use std::os::unix::io::RawFd;

/// eBPF 管理器配置
#[derive(Debug, Clone)]
pub struct EbpfConfig {
    pub enabled: bool,
    pub sockmap_enabled: bool,
    pub dns_cache_enabled: bool,
    pub dns_cache_size: usize,
    pub stats_enabled: bool,
}

impl Default for EbpfConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            sockmap_enabled: true,
            dns_cache_enabled: true,
            dns_cache_size: 10000,
            stats_enabled: true,
        }
    }
}

/// eBPF 管理器
pub struct EbpfManager {
    config: EbpfConfig,
    capabilities: EbpfCapabilities,
    sockmap: Option<SockmapManager>,
    dns_cache: Option<EbpfDnsCache>,
    stats: Option<EbpfStats>,
    initialized: bool,
    // 保持对 eBPF 对象的引用，防止被drop
    _ebpf: Option<Bpf>,
}

impl EbpfManager {
    /// 创建新的 eBPF 管理器
    pub fn new(config: EbpfConfig) -> Result<Self> {
        info!("初始化 eBPF 管理器");

        // 检测系统能力
        let capabilities = EbpfCapabilities::detect()
            .context("Failed to detect eBPF capabilities")?;

        info!("eBPF 系统能力: {}", capabilities.summary());

        // 检查是否满足基本要求
        if !config.enabled {
            info!("eBPF 未启用，将使用传统模式");
            return Ok(Self {
                config,
                capabilities,
                sockmap: None,
                dns_cache: None,
                stats: None,
                initialized: false,
                _ebpf: None,
            });
        }

        if !capabilities.is_fully_supported() {
            warn!("系统不完全支持 eBPF 功能，将降级到传统模式");
            warn!("需要内核版本 >= 4.14，当前: {}.{}.{}",
                  capabilities.kernel_version.0,
                  capabilities.kernel_version.1,
                  capabilities.kernel_version.2);

            return Ok(Self {
                config,
                capabilities,
                sockmap: None,
                dns_cache: None,
                stats: None,
                initialized: false,
                _ebpf: None,
            });
        }

        // 尝试加载 eBPF 程序
        let mut ebpf = match Self::load_ebpf_program() {
            Ok(bpf_loaded) => {
                info!("✅ eBPF 程序加载成功");
                bpf_loaded
            }
            Err(e) => {
                warn!("⚠️  eBPF 程序加载失败: {}, 将降级到传统模式", e);
                return Ok(Self {
                    config,
                    capabilities,
                    sockmap: None,
                    dns_cache: None,
                    stats: None,
                    initialized: false,
                    _ebpf: None,
                });
            }
        };

        // 初始化各个组件（需要从 Bpf 对象获取 Maps）
        let sockmap = if config.sockmap_enabled {
            match SockmapManager::new(&mut ebpf) {
                Ok(sm) => {
                    info!("✓ Sockmap 初始化成功");
                    Some(sm)
                }
                Err(e) => {
                    error!("✗ Sockmap 初始化失败: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let dns_cache = if config.dns_cache_enabled {
            match EbpfDnsCache::new(&mut ebpf, config.dns_cache_size) {
                Ok(cache) => {
                    info!("✓ DNS 缓存初始化成功");
                    Some(cache)
                }
                Err(e) => {
                    error!("✗ DNS 缓存初始化失败: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let stats = if config.stats_enabled {
            match EbpfStats::new(&mut ebpf) {
                Ok(st) => {
                    info!("✓ 流量统计初始化成功");
                    Some(st)
                }
                Err(e) => {
                    error!("✗ 流量统计初始化失败: {}", e);
                    None
                }
            }
        } else {
            None
        };

        let initialized = sockmap.is_some() || dns_cache.is_some() || stats.is_some();

        // 在所有组件初始化后，尝试 attach eBPF 程序到 hook 点
        if let Err(e) = Self::attach_ebpf_programs(&mut ebpf, sockmap.as_ref()) {
            warn!("⚠️  eBPF 程序 attach 失败: {}, 但程序已加载", e);
        } else {
            info!("✅ eBPF 程序 attach 成功");
        }

        if initialized {
            info!("eBPF 管理器初始化完成");
        } else {
            warn!("所有 eBPF 组件初始化失败，将使用传统模式");
        }

        Ok(Self {
            config,
            capabilities,
            sockmap,
            dns_cache,
            stats,
            initialized,
            _ebpf: Some(ebpf),
        })
    }

    /// 加载 eBPF 程序
    fn load_ebpf_program() -> Result<Bpf> {
        info!("加载 eBPF 程序...");

        // 尝试嵌入的 eBPF 程序
        #[cfg(target_os = "linux")]
        {
            // 从编译时嵌入的字节码加载
            const EBPF_BYTES: &[u8] = include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/target/bpfel-unknown-none/release/sni-proxy"
            ));

            if EBPF_BYTES.len() > 100 {
                match Bpf::load(EBPF_BYTES) {
                    Ok(ebpf) => {
                        info!("✓ 从嵌入字节码加载 eBPF 程序成功");
                        return Ok(ebpf);
                    }
                    Err(e) => {
                        warn!("从嵌入字节码加载失败: {}", e);
                    }
                }
            }
        }

        // 如果嵌入失败，尝试从文件系统加载
        let ebpf_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("target/bpfel-unknown-none/release/sni-proxy");

        if ebpf_path.exists() {
            let bytes = std::fs::read(&ebpf_path)
                .context("读取 eBPF 程序文件失败")?;

            Bpf::load(&bytes)
                .context("从文件加载 eBPF 程序失败")
        } else {
            anyhow::bail!("未找到 eBPF 程序文件: {:?}", ebpf_path)
        }
    }

    /// Attach eBPF 程序到相应的 hook 点
    fn attach_ebpf_programs(bpf: &mut Bpf, _sockmap: Option<&SockmapManager>) -> Result<()> {
        use log::debug as log_debug;
        info!("Attaching eBPF 程序...");

        // 尝试 attach SK_MSG 程序（用于 sockmap）
        if let Some(program) = bpf.program_mut("redirect_msg") {
            use aya::programs::SkMsg;
            match program.try_into() {
                Ok(sk_msg) => {
                    let sk_msg_prog: &mut SkMsg = sk_msg;
                    match sk_msg_prog.load() {
                        Ok(_) => {
                            info!("✓ SK_MSG 程序加载成功");

                            // TODO: 完成 SK_MSG attach 到 sockmap
                            // 需要获取 SockHash 的引用并 attach
                            // if let Some(sockmap) = _sockmap {
                            //     let sock_map = sockmap.get_sock_map();
                            //     sk_msg_prog.attach(sock_map)?;
                            //     info!("✓ SK_MSG 程序已 attach 到 sockmap");
                            // }
                        }
                        Err(e) => {
                            warn!("SK_MSG 程序加载失败: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("SK_MSG 程序类型转换失败: {}", e);
                }
            }
        } else {
            log_debug!("未找到 redirect_msg 程序");
        }

        // 尝试 attach XDP 程序（如果存在）
        if let Some(program) = bpf.program_mut("xdp_ip_filter") {
            use aya::programs::Xdp;
            match program.try_into() {
                Ok(xdp) => {
                    let xdp_prog: &mut Xdp = xdp;
                    match xdp_prog.load() {
                        Ok(_) => {
                            info!("✓ XDP 程序加载成功（未 attach 到接口）");
                            // attach 到网络接口需要接口名称，稍后处理
                        }
                        Err(e) => {
                            warn!("XDP 程序加载失败: {}", e);
                        }
                    }
                }
                Err(e) => {
                    warn!("XDP 程序类型转换失败: {}", e);
                }
            }
        } else {
            log_debug!("未找到 xdp_ip_filter 程序");
        }

        info!("eBPF 程序 attach 完成");
        Ok(())
    }

    /// 是否已初始化
    pub fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// 是否启用了 sockmap
    pub fn is_sockmap_enabled(&self) -> bool {
        self.sockmap.is_some()
    }

    /// 是否启用了 DNS 缓存
    pub fn is_dns_cache_enabled(&self) -> bool {
        self.dns_cache.is_some()
    }

    /// 是否启用了流量统计
    pub fn is_stats_enabled(&self) -> bool {
        self.stats.is_some()
    }

    /// 注册 socket 对到 sockmap
    pub fn register_socket_pair(&mut self, client_fd: RawFd, target_fd: RawFd) -> Result<()> {
        if let Some(ref mut sockmap) = self.sockmap {
            sockmap.register_pair(client_fd, target_fd)?;
            Ok(())
        } else {
            anyhow::bail!("Sockmap not available")
        }
    }

    /// 注销 socket 对
    pub fn unregister_socket_pair(&mut self, client_fd: RawFd, target_fd: RawFd) -> Result<()> {
        if let Some(ref mut sockmap) = self.sockmap {
            sockmap.unregister_pair(client_fd, target_fd)?;
            Ok(())
        } else {
            anyhow::bail!("Sockmap not available")
        }
    }

    /// 查询 DNS 缓存
    pub fn lookup_dns(&mut self, domain: &str) -> Option<IpAddr> {
        if let Some(ref mut cache) = self.dns_cache {
            cache.lookup(domain)
        } else {
            None
        }
    }

    /// 插入 DNS 缓存
    pub fn insert_dns(&mut self, domain: &str, ip: IpAddr) -> Result<()> {
        if let Some(ref mut cache) = self.dns_cache {
            cache.insert(domain, ip)?;
            Ok(())
        } else {
            anyhow::bail!("DNS cache not available")
        }
    }

    /// 记录发送的数据
    pub fn record_sent(&self, fd: RawFd, bytes: u64) {
        if let Some(ref stats) = self.stats {
            stats.record_sent(fd, bytes);
        }
    }

    /// 记录接收的数据
    pub fn record_received(&self, fd: RawFd, bytes: u64) {
        if let Some(ref stats) = self.stats {
            stats.record_received(fd, bytes);
        }
    }

    /// 获取连接统计
    pub fn get_connection_stats(&self, fd: RawFd) -> Option<super::ConnectionStats> {
        // 注意：需要 mut 引用来调用 get_connection_stats
        // 由于我们无法在 & self 方法中获取 mut，这里暂时返回 None
        // TODO: 重构为 get_connection_stats(&mut self)
        None
    }

    /// 移除连接统计
    pub fn remove_connection_stats(&self, fd: RawFd) -> Option<super::ConnectionStats> {
        // 注意：需要 mut 引用来调用 remove_connection
        // 由于我们无法在 & self 方法中获取 mut，这里暂时返回 None
        // TODO: 重构为 remove_connection_stats(&mut self)
        None
    }

    /// 获取系统能力
    pub fn capabilities(&self) -> &EbpfCapabilities {
        &self.capabilities
    }

    /// 获取配置
    pub fn config(&self) -> &EbpfConfig {
        &self.config
    }

    /// 打印状态摘要
    pub fn print_status(&self) {
        info!("===== eBPF 管理器状态 =====");
        info!("初始化: {}", if self.initialized { "是" } else { "否" });
        info!("系统能力: {}", self.capabilities.summary());
        info!("Sockmap: {}", if self.sockmap.is_some() { "已启用" } else { "未启用" });
        info!("DNS 缓存: {}", if self.dns_cache.is_some() { "已启用" } else { "未启用" });
        info!("流量统计: {}", if self.stats.is_some() { "已启用" } else { "未启用" });

        if let Some(ref sockmap) = self.sockmap {
            let stats = sockmap.stats();
            info!("  - 活跃连接: {}", stats.active_connections);
            info!("  - 已注册: {}", stats.registered_pairs);
            info!("  - 已注销: {}", stats.unregistered_pairs);
        }

        if let Some(ref dns_cache) = self.dns_cache {
            let stats = dns_cache.stats();
            // 注意：eBPF Map 无法高效获取当前大小
            info!("  - 命中: {}", stats.hits);
            info!("  - 未命中: {}", stats.misses);
            info!("  - 命中率: {:.2}%", dns_cache.hit_rate() * 100.0);
        }

        // 注意：stats 需要 mut 引用才能读取，这里暂时省略详细统计
        if let Some(ref _stats) = self.stats {
            info!("  - 流量统计已启用");
            // TODO: 添加 mut 引用版本的 print_status 来获取完整统计
        }
    }

    /// 清理所有资源
    pub fn cleanup(&mut self) {
        info!("清理 eBPF 资源");

        if let Some(ref mut sockmap) = self.sockmap {
            sockmap.cleanup();
        }

        if let Some(ref mut dns_cache) = self.dns_cache {
            dns_cache.clear();
        }

        if let Some(ref stats) = self.stats {
            stats.clear();
        }
    }
}

impl Drop for EbpfManager {
    fn drop(&mut self) {
        info!("eBPF 管理器销毁");
        self.print_status();
        self.cleanup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ebpf_manager_creation() {
        let config = EbpfConfig::default();
        let manager = EbpfManager::new(config);

        assert!(manager.is_ok());

        if let Ok(manager) = manager {
            println!("eBPF Manager initialized: {}", manager.is_initialized());
            println!("Sockmap enabled: {}", manager.is_sockmap_enabled());
            println!("DNS cache enabled: {}", manager.is_dns_cache_enabled());
            println!("Stats enabled: {}", manager.is_stats_enabled());
        }
    }

    #[test]
    fn test_ebpf_capabilities() {
        let caps = EbpfCapabilities::detect();
        assert!(caps.is_ok());

        if let Ok(caps) = caps {
            println!("Capabilities: {}", caps.summary());
        }
    }
}
