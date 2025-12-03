use anyhow::Result;
use log::debug;
use std::net::IpAddr;
use tokio::net::TcpStream;

use crate::ip_traffic::IpTrafficTracker;
use crate::metrics::Metrics;

/// 优化 TCP socket 参数（流媒体专用）
///
/// 为流媒体场景优化 TCP 参数：
/// - 更大的接收/发送缓冲区 (1MB)
/// - TCP_NODELAY 避免 Nagle 算法延迟
#[allow(unused_variables)]
pub fn optimize_tcp_for_streaming(stream: &TcpStream) -> Result<()> {
    // 设置 TCP_NODELAY（禁用 Nagle 算法，减少延迟）
    let _ = stream.set_nodelay(true);

    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        let fd = stream.as_raw_fd();

        // 设置接收缓冲区为 1MB（流媒体需要大缓冲）
        unsafe {
            let rcvbuf_size: libc::c_int = 1024 * 1024; // 1MB
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &rcvbuf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );

            // 设置发送缓冲区为 1MB
            let sndbuf_size: libc::c_int = 1024 * 1024; // 1MB
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &sndbuf_size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }

    Ok(())
}

/// 双向代理数据传输（流媒体优化版本）
/// ⚡ 优化：使用 tokio 零拷贝 + 批量统计，专为 Netflix/Disney+/HBO Max 等流媒体优化
///
/// 性能优化：
/// 1. 使用 tokio::io::copy_bidirectional（内核级零拷贝）
/// 2. 批量更新统计数据，减少原子操作开销
/// 3. 避免手动缓冲区管理
pub async fn proxy_data(
    mut client_stream: TcpStream,
    mut target_stream: TcpStream,
    metrics: Metrics,
    client_ip: IpAddr,
    ip_traffic_tracker: IpTrafficTracker,
) -> Result<()> {
    // 使用 tokio 的零拷贝双向传输（性能最优）
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
