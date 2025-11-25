use anyhow::Result;
use log::debug;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::metrics::Metrics;

/// 双向代理数据传输（优化版本）
/// ⚡ 优化：更大的缓冲区提高吞吐量
pub async fn proxy_data(
    client_stream: TcpStream,
    target_stream: TcpStream,
    metrics: Metrics,
) -> Result<()> {
    let (mut client_read, mut client_write) = client_stream.into_split();
    let (mut target_read, mut target_write) = target_stream.into_split();

    // ⚡ 优化：使用 64KB 缓冲区（从 16KB）以提高吞吐量
    let metrics_c2t = metrics.clone();
    let client_to_target = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match client_read.read(&mut buf).await {
                Ok(0) => return Ok::<(), std::io::Error>(()),
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            target_write.write_all(&buf[..n]).await?;
            metrics_c2t.add_bytes_received(n as u64);
        }
    };

    let metrics_t2c = metrics.clone();
    let target_to_client = async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let n = match target_read.read(&mut buf).await {
                Ok(0) => return Ok::<(), std::io::Error>(()),
                Ok(n) => n,
                Err(e) => return Err(e),
            };
            client_write.write_all(&buf[..n]).await?;
            metrics_t2c.add_bytes_sent(n as u64);
        }
    };

    tokio::select! {
        result = client_to_target => {
            if let Err(e) = result {
                debug!("客户端到目标服务器的数据传输结束: {}", e);
            }
        }
        result = target_to_client => {
            if let Err(e) = result {
                debug!("目标服务器到客户端的数据传输结束: {}", e);
            }
        }
    }

    Ok(())
}
