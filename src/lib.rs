// 模块声明
pub mod dns;
pub mod domain;
pub mod ip_matcher;
pub mod ip_traffic;
pub mod logger;
pub mod metrics;
pub mod proxy;
pub mod server;
pub mod socks5;
pub mod tls;

// 重新导出主要的公共类型和函数
pub use dns::{clear_dns_cache, get_dns_cache_size, resolve_host_cached};
pub use domain::DomainMatcher;
pub use ip_matcher::IpMatcher;
pub use ip_traffic::{IpTrafficTracker, IpTrafficSnapshot};
pub use logger::{init_default_logger, init_from_env, init_logger, LogConfig, LogLevel};
pub use metrics::{Metrics, MetricsSnapshot};
pub use proxy::proxy_data;
pub use server::SniProxy;
pub use socks5::{connect_via_socks5, Socks5Config};
pub use tls::parse_sni;
