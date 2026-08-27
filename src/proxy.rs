use anyhow::Result;
use log::debug;
use std::net::IpAddr;
use tokio::net::TcpStream;

use crate::ip_traffic::IpTrafficTracker;
use crate::metrics::Metrics;

/// 优化 TCP socket 参数（流媒体专用）
///
/// - TCP_NODELAY 禁用 Nagle 算法减少延迟
///
/// 注意：不再手动设置 SO_RCVBUF/SO_SNDBUF。之前固定设为 1MB，
/// 在大量并发连接下（客户端+目标两侧 socket 各占一份）会强制预留
/// 远超实际需要的内核缓冲区，且绕过了 Linux 默认的自动调优
/// （会根据实际吞吐动态伸缩），高并发时反而增加内存压力、损害延迟稳定性。
/// 交给内核自动调优即可。
pub fn optimize_tcp_for_streaming(stream: &TcpStream) -> Result<()> {
    // 设置 TCP_NODELAY（禁用 Nagle 算法，减少延迟）
    let _ = stream.set_nodelay(true);

    Ok(())
}

/// 双向代理数据传输（流媒体优化版本）
///
/// 性能优化：
/// 1. 使用 tokio::io::copy_bidirectional（Tokio 内部缓冲，避免手动缓冲区管理）
/// 2. 连接结束后批量更新统计数据，减少原子操作开销
pub async fn proxy_data(
    mut client_stream: TcpStream,
    mut target_stream: TcpStream,
    metrics: Metrics,
    client_ip: IpAddr,
    ip_traffic_tracker: IpTrafficTracker,
) -> Result<()> {
    match tokio::io::copy_bidirectional(&mut client_stream, &mut target_stream).await {
        Ok((client_to_target, target_to_client)) => {
            // 批量更新统计（只在连接结束时更新一次）
            metrics.add_bytes_received(client_to_target);
            metrics.add_bytes_sent(target_to_client);

            // 批量更新 IP 流量统计
            ip_traffic_tracker.record_received(client_ip, client_to_target);
            ip_traffic_tracker.record_sent(client_ip, target_to_client);

            debug!(
                "数据传输完成: 上传 {} bytes, 下载 {} bytes",
                client_to_target, target_to_client
            );
        }
        Err(e) => {
            debug!("数据传输结束: {}", e);
        }
    }

    Ok(())
}
