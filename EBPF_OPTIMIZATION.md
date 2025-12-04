# eBPF 优化 SNI-Proxy 方案

## 1. 方案概述

本文档描述了如何使用 eBPF (Extended Berkeley Packet Filter) 技术优化 SNI-Proxy 的性能。eBPF 允许我们在 Linux 内核空间运行安全的程序，可以显著减少数据包处理延迟和 CPU 开销。

### 1.1 优化目标

- **延迟降低**: 减少 30-50% 的连接建立延迟
- **吞吐量提升**: 提升 50-100% 的数据转发吞吐量
- **CPU 开销降低**: 减少 40-60% 的 CPU 使用率
- **扩展性提升**: 支持 100K+ 并发连接

### 1.2 eBPF 优化技术栈

```
┌─────────────────────────────────────────────────┐
│          应用层 (Rust + Tokio)                    │
│  - 配置管理                                      │
│  - 策略决策 (域名/IP 白名单)                      │
│  - 监控和日志                                    │
└─────────────────────────────────────────────────┘
                    ↕ (控制平面)
┌─────────────────────────────────────────────────┐
│          eBPF 层 (内核空间)                       │
│  - Sockmap 数据转发                              │
│  - DNS 缓存 (BPF Map)                            │
│  - 流量统计 (BPF Map)                            │
│  - 连接跟踪 (BPF Map)                            │
└─────────────────────────────────────────────────┘
                    ↕ (数据平面)
┌─────────────────────────────────────────────────┐
│          网络层                                   │
│  - TCP/IP 协议栈                                 │
│  - 网络接口卡                                    │
└─────────────────────────────────────────────────┘
```

## 2. 核心优化技术

### 2.1 Sockmap/Sockhash - 内核级数据转发

#### 原理

Sockmap 是 eBPF 提供的一种特殊 Map 类型，可以存储 socket 文件描述符。配合 `BPF_PROG_TYPE_SK_SKB` 程序，可以在内核空间直接转发数据，**完全绕过用户态**。

#### 数据流对比

**传统方式**:
```
客户端 socket → 内核缓冲区 → 用户态读取 → 用户态写入 → 内核缓冲区 → 目标 socket
         (系统调用)      (拷贝)       (处理)       (拷贝)      (系统调用)
延迟: ~50-100μs，CPU 密集
```

**eBPF Sockmap**:
```
客户端 socket → 内核缓冲区 → [eBPF 程序] → 目标 socket
                           (直接重定向，零拷贝)
延迟: ~5-10μs，CPU 开销极低
```

#### 性能提升

- **延迟**: 降低 80-90%（100μs → 10μs）
- **吞吐量**: 提升 2-3 倍
- **CPU 使用**: 降低 50-70%

### 2.2 eBPF Map - 高性能数据共享

#### DNS 缓存优化

**当前实现问题**:
```rust
// 全局 Mutex，高并发时锁竞争严重
lazy_static! {
    static ref DNS_CACHE: Mutex<LruCache<String, Vec<IpAddr>>> = ...;
}
```

**eBPF 优化方案**:
```c
// eBPF Hash Map，无锁并发访问
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10000);
    __type(key, struct dns_key);    // 域名哈希
    __type(value, struct dns_value);  // IP 地址 + TTL
} dns_cache_map SEC(".maps");

// 查询延迟: Mutex 锁 ~1-10μs → eBPF Map ~0.1μs
```

**优势**:
- 无锁设计，完全并发
- 内核空间访问，零系统调用
- 支持 LRU 自动淘汰
- 用户态和内核态共享

#### 流量统计优化

**eBPF Per-CPU Map**:
```c
// 每个 CPU 核心独立计数，避免原子操作竞争
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct traffic_stats);
} traffic_stats_map SEC(".maps");

struct traffic_stats {
    __u64 bytes_sent;
    __u64 bytes_received;
    __u64 packets_sent;
    __u64 packets_received;
};

// 性能: 原子操作 ~20ns → Per-CPU 访问 ~2ns
```

### 2.3 XDP (eXpress Data Path) - 网卡层过滤

#### 原理

XDP 程序运行在网卡驱动层，可以在数据包进入协议栈之前进行处理，适合做早期过滤和负载均衡。

#### 应用场景

1. **IP 白名单过滤**
   ```c
   SEC("xdp")
   int xdp_ip_whitelist(struct xdp_md *ctx) {
       // 解析 IP 头
       // 检查源 IP 是否在白名单
       // 不在白名单: return XDP_DROP;  // 直接丢弃
       // 在白名单: return XDP_PASS;     // 继续处理
   }
   ```
   **性能**:
   - 传统过滤: 数据包到达用户态 → 检查 → 拒绝 → ~100μs
   - XDP 过滤: 网卡层直接丢弃 → ~1-2μs
   - CPU 节省: 拒绝的连接不再消耗 CPU

2. **DDoS 防护**
   - 在网卡层限流
   - 检测 SYN Flood
   - 保护用户态服务

3. **负载均衡**
   - 根据源 IP 哈希分发到多个代理实例
   - 内核级负载均衡，零延迟

### 2.4 eBPF TC (Traffic Control) - 流量整形

#### 应用场景

1. **QoS (服务质量)**
   - 为不同域名分配不同优先级
   - 流媒体优先（Netflix/Disney+）
   - 降低非关键流量优先级

2. **带宽限制**
   - 为每个 IP 设置带宽上限
   - 防止单个客户端占用全部带宽

## 3. 架构设计

### 3.1 混合架构

```
┌──────────────────────────────────────────────────────┐
│  用户态 (Rust)                                         │
│  ┌────────────────────────────────────────────────┐  │
│  │  控制平面                                        │  │
│  │  - 加载 eBPF 程序                               │  │
│  │  - 管理 eBPF Map                                │  │
│  │  - SNI 解析 & 域名匹配                          │  │
│  │  - 策略决策                                     │  │
│  │  - 监控和日志                                   │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
                         ↕
        (通过 BPF Map 和 系统调用通信)
                         ↕
┌──────────────────────────────────────────────────────┐
│  内核态 (eBPF)                                         │
│  ┌────────────────────────────────────────────────┐  │
│  │  数据平面                                        │  │
│  │  - Sockmap 数据转发                             │  │
│  │  - DNS 缓存查询                                 │  │
│  │  - 流量统计                                     │  │
│  │  - 连接跟踪                                     │  │
│  └────────────────────────────────────────────────┘  │
│  ┌────────────────────────────────────────────────┐  │
│  │  XDP 程序                                        │  │
│  │  - IP 白名单过滤                                │  │
│  │  - 早期丢包                                     │  │
│  └────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────┘
```

### 3.2 工作流程

#### 连接建立阶段

1. **客户端连接到达**
   - XDP 程序检查 IP 白名单（可选）
   - 通过：进入协议栈
   - 拒绝：XDP_DROP，零开销

2. **用户态接受连接**
   ```rust
   let (client_stream, client_addr) = listener.accept().await?;
   let client_fd = client_stream.as_raw_fd();
   ```

3. **读取 TLS Client Hello & 解析 SNI**
   ```rust
   let sni_domain = parse_sni(&buffer)?;
   ```

4. **域名白名单检查**
   ```rust
   if !domain_matcher.is_match(&sni_domain) {
       return Err("Domain not allowed");
   }
   ```

5. **DNS 查询（优先使用 eBPF Map 缓存）**
   ```rust
   // 先查询 eBPF DNS 缓存
   if let Some(ip) = ebpf_dns_cache_lookup(&sni_domain) {
       // 缓存命中，零延迟
   } else {
       // 缓存未命中，执行异步 DNS 查询
       let ip = tokio::net::lookup_host(&sni_domain).await?;
       // 更新 eBPF Map
       ebpf_dns_cache_insert(&sni_domain, ip);
   }
   ```

6. **连接目标服务器**
   ```rust
   let target_stream = TcpStream::connect(target_addr).await?;
   let target_fd = target_stream.as_raw_fd();
   ```

7. **注册到 Sockmap**
   ```rust
   // 建立 client_fd → target_fd 的映射
   ebpf_sockmap_insert(client_fd, target_fd)?;
   // 建立 target_fd → client_fd 的映射（双向）
   ebpf_sockmap_insert(target_fd, client_fd)?;
   ```

#### 数据转发阶段

**传统方式（用户态）**:
```rust
// 需要持续运行循环
tokio::io::copy_bidirectional(&mut client_stream, &mut target_stream).await?;
```

**eBPF 方式（内核态）**:
```c
SEC("sk_skb/stream_verdict")
int bpf_sk_skb_redirect(struct __sk_buff *skb) {
    // 1. 获取当前 socket 的 key
    __u64 current_fd = bpf_get_socket_cookie(skb);

    // 2. 在 sockmap 中查找对端 socket
    struct bpf_sock *peer = bpf_map_lookup_elem(&sock_map, &current_fd);
    if (!peer) {
        return SK_PASS;  // 未找到，交给用户态处理
    }

    // 3. 直接重定向数据到对端（零拷贝）
    return bpf_sk_skb_redirect_map(skb, &sock_map, peer_fd, 0);

    // 用户态完全不参与数据转发！
}
```

**用户态角色**:
```rust
// 用户态只需要等待连接关闭
let result = wait_for_connection_close(client_fd, target_fd).await;

// 清理资源
ebpf_sockmap_remove(client_fd)?;
ebpf_sockmap_remove(target_fd)?;

// 更新统计（从 eBPF Map 读取）
let stats = ebpf_read_traffic_stats(client_fd)?;
metrics.add_bytes_received(stats.bytes_received);
metrics.add_bytes_sent(stats.bytes_sent);
```

#### 连接关闭阶段

1. **检测连接关闭**
   ```rust
   // 监听 socket 事件
   // 或者 eBPF 程序通知用户态
   ```

2. **清理 Sockmap**
   ```rust
   ebpf_sockmap_remove(client_fd)?;
   ebpf_sockmap_remove(target_fd)?;
   ```

3. **读取统计信息**
   ```rust
   let stats = ebpf_get_connection_stats(client_fd)?;
   ```

4. **关闭 socket**
   ```rust
   client_stream.shutdown()?;
   target_stream.shutdown()?;
   ```

## 4. 实现方案

### 4.1 技术选型

#### Rust eBPF 框架

推荐使用 **Aya**（最现代的 Rust eBPF 框架）:

```toml
[dependencies]
aya = "0.12"
aya-log = "0.2"

[build-dependencies]
aya-bpf = "0.1"
```

**优势**:
- 纯 Rust 实现，无需 C 工具链
- 类型安全，编译时检查
- 现代化 API，易于使用
- 活跃维护，社区支持好

**替代方案**:
- **libbpf-rs**: libbpf 的 Rust 绑定，需要 C 工具链
- **redbpf**: 较早的项目，不太活跃

### 4.2 项目结构

```
sni-proxy/
├── src/
│   ├── main.rs                 # 主程序
│   ├── server.rs               # 代理服务器
│   ├── ebpf/                   # eBPF 集成模块
│   │   ├── mod.rs              # 模块入口
│   │   ├── sockmap.rs          # Sockmap 管理
│   │   ├── dns_cache.rs        # eBPF DNS 缓存
│   │   ├── stats.rs            # eBPF 流量统计
│   │   └── xdp.rs              # XDP 程序管理（可选）
│   └── ...
├── ebpf/                       # eBPF 程序（内核态）
│   ├── src/
│   │   ├── main.rs             # eBPF 入口
│   │   ├── sockmap.rs          # Socket 重定向
│   │   ├── dns_cache.rs        # DNS 缓存 Map
│   │   ├── stats.rs            # 流量统计
│   │   └── xdp.rs              # XDP 程序（可选）
│   └── Cargo.toml
└── Cargo.toml
```

### 4.3 eBPF 程序实现

#### sockmap.rs (内核态)

```rust
// ebpf/src/sockmap.rs
#![no_std]
#![no_main]

use aya_bpf::{
    bindings::BPF_F_INGRESS,
    macros::{map, sk_msg},
    maps::{HashMap, SockHash},
    programs::SkMsgContext,
};

// Socket 映射表: fd → 对端 fd
#[map]
static mut SOCK_MAP: SockHash<u32> = SockHash::with_max_entries(65536, 0);

// 连接映射表: client_fd → target_fd
#[map]
static mut CONNECTION_MAP: HashMap<u32, u32> = HashMap::with_max_entries(65536, 0);

#[sk_msg]
pub fn redirect_msg(ctx: SkMsgContext) -> u32 {
    match try_redirect_msg(&ctx) {
        Ok(action) => action,
        Err(_) => 1, // SK_PASS: 交给用户态处理
    }
}

fn try_redirect_msg(ctx: &SkMsgContext) -> Result<u32, ()> {
    // 获取当前 socket 的 key
    let local_port = ctx.local_port();
    let remote_port = ctx.remote_port();

    // 构建查找 key
    let key = (local_port as u32) << 16 | remote_port as u32;

    // 查找对端 socket
    unsafe {
        if let Some(peer_key) = CONNECTION_MAP.get(&key) {
            // 重定向到对端（零拷贝）
            SOCK_MAP.redirect_msg(ctx, peer_key, BPF_F_INGRESS as u64)?;
            return Ok(0); // SK_DROP: 已重定向，丢弃原数据
        }
    }

    Ok(1) // SK_PASS: 未找到映射，交给用户态
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
```

#### sockmap.rs (用户态)

```rust
// src/ebpf/sockmap.rs
use aya::{
    maps::{HashMap, SockHash},
    programs::{SkMsg, SocketMap},
    Bpf,
};
use std::os::unix::io::RawFd;
use anyhow::Result;

pub struct SockmapManager {
    sock_map: SockHash<HashMap<u32, u32>>,
    connection_map: HashMap<u32, u32>,
}

impl SockmapManager {
    pub fn new(bpf: &mut Bpf) -> Result<Self> {
        // 获取 eBPF Map 引用
        let sock_map = SockHash::try_from(bpf.map_mut("SOCK_MAP")?)?;
        let connection_map = HashMap::try_from(bpf.map_mut("CONNECTION_MAP")?)?;

        Ok(Self {
            sock_map,
            connection_map,
        })
    }

    /// 注册 socket 对到 sockmap
    pub fn register_pair(&mut self, client_fd: RawFd, target_fd: RawFd) -> Result<()> {
        // 构建 key
        let client_key = self.make_key(client_fd)?;
        let target_key = self.make_key(target_fd)?;

        // 双向映射
        self.connection_map.insert(client_key, target_key, 0)?;
        self.connection_map.insert(target_key, client_key, 0)?;

        // 添加到 sockmap
        self.sock_map.insert(client_key, client_fd, 0)?;
        self.sock_map.insert(target_key, target_fd, 0)?;

        Ok(())
    }

    /// 注销 socket 对
    pub fn unregister_pair(&mut self, client_fd: RawFd, target_fd: RawFd) -> Result<()> {
        let client_key = self.make_key(client_fd)?;
        let target_key = self.make_key(target_fd)?;

        self.connection_map.remove(&client_key)?;
        self.connection_map.remove(&target_key)?;
        self.sock_map.remove(&client_key)?;
        self.sock_map.remove(&target_key)?;

        Ok(())
    }

    fn make_key(&self, fd: RawFd) -> Result<u32> {
        // 从 fd 获取端口信息构建 key
        // 实现细节...
        Ok(fd as u32)
    }
}
```

#### dns_cache.rs (eBPF Map)

```rust
// src/ebpf/dns_cache.rs
use aya::{
    maps::lru_hash_map::LruHashMap,
    Bpf,
};
use std::net::IpAddr;
use anyhow::Result;

pub struct EbpfDnsCache {
    cache_map: LruHashMap<[u8; 256], [u8; 16]>,  // 域名 → IP
}

impl EbpfDnsCache {
    pub fn new(bpf: &mut Bpf) -> Result<Self> {
        let cache_map = LruHashMap::try_from(bpf.map_mut("DNS_CACHE_MAP")?)?;
        Ok(Self { cache_map })
    }

    /// 查询 DNS 缓存
    pub fn lookup(&self, domain: &str) -> Result<Option<IpAddr>> {
        let key = self.domain_to_key(domain);

        if let Some(value) = self.cache_map.get(&key, 0)? {
            let ip = self.bytes_to_ip(&value);
            return Ok(Some(ip));
        }

        Ok(None)
    }

    /// 插入 DNS 缓存
    pub fn insert(&mut self, domain: &str, ip: IpAddr) -> Result<()> {
        let key = self.domain_to_key(domain);
        let value = self.ip_to_bytes(ip);

        self.cache_map.insert(key, value, 0)?;
        Ok(())
    }

    fn domain_to_key(&self, domain: &str) -> [u8; 256] {
        let mut key = [0u8; 256];
        let bytes = domain.as_bytes();
        let len = bytes.len().min(256);
        key[..len].copy_from_slice(&bytes[..len]);
        key
    }

    fn ip_to_bytes(&self, ip: IpAddr) -> [u8; 16] {
        let mut bytes = [0u8; 16];
        match ip {
            IpAddr::V4(ipv4) => {
                bytes[..4].copy_from_slice(&ipv4.octets());
            }
            IpAddr::V6(ipv6) => {
                bytes.copy_from_slice(&ipv6.octets());
            }
        }
        bytes
    }

    fn bytes_to_ip(&self, bytes: &[u8; 16]) -> IpAddr {
        // 实现细节...
        IpAddr::V4(std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
    }
}
```

### 4.4 集成到现有代码

#### 修改 server.rs

```rust
// src/server.rs
use crate::ebpf::{SockmapManager, EbpfDnsCache};

pub struct SniProxy {
    // 现有字段...

    // 新增 eBPF 管理器
    sockmap_manager: Option<SockmapManager>,
    ebpf_dns_cache: Option<EbpfDnsCache>,
    ebpf_enabled: bool,
}

impl SniProxy {
    pub async fn new(config: Config) -> Result<Self> {
        // 尝试加载 eBPF 程序
        let (sockmap_manager, ebpf_dns_cache, ebpf_enabled) =
            match Self::load_ebpf() {
                Ok((sm, dns)) => {
                    info!("eBPF 程序加载成功，将使用内核级加速");
                    (Some(sm), Some(dns), true)
                }
                Err(e) => {
                    warn!("eBPF 程序加载失败: {}，将使用传统模式", e);
                    (None, None, false)
                }
            };

        Ok(Self {
            // 现有初始化...
            sockmap_manager,
            ebpf_dns_cache,
            ebpf_enabled,
        })
    }

    fn load_ebpf() -> Result<(SockmapManager, EbpfDnsCache)> {
        // 加载 eBPF 程序
        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpf/programs/sni_proxy"
        ))?;

        // 附加 SkMsg 程序
        let program: &mut SkMsg = bpf.program_mut("redirect_msg")?.try_into()?;
        program.load()?;
        program.attach(&sock_map)?;

        // 创建管理器
        let sockmap_manager = SockmapManager::new(&mut bpf)?;
        let ebpf_dns_cache = EbpfDnsCache::new(&mut bpf)?;

        Ok((sockmap_manager, ebpf_dns_cache))
    }

    async fn handle_connection(&self, ...) -> Result<()> {
        // ... 现有代码：接受连接、解析 SNI、域名检查 ...

        // DNS 查询（优先使用 eBPF 缓存）
        let target_ip = if self.ebpf_enabled {
            if let Some(ip) = self.ebpf_dns_cache.as_ref()
                .and_then(|cache| cache.lookup(&sni_domain).ok().flatten()) {
                info!("eBPF DNS 缓存命中: {} → {}", sni_domain, ip);
                ip
            } else {
                let ip = self.resolve_dns(&sni_domain).await?;
                // 更新 eBPF 缓存
                if let Some(cache) = &mut self.ebpf_dns_cache {
                    cache.insert(&sni_domain, ip)?;
                }
                ip
            }
        } else {
            self.resolve_dns(&sni_domain).await?
        };

        // 连接目标服务器
        let target_stream = TcpStream::connect((target_ip, 443)).await?;

        // 如果启用了 eBPF，注册到 sockmap
        if self.ebpf_enabled {
            let client_fd = client_stream.as_raw_fd();
            let target_fd = target_stream.as_raw_fd();

            if let Some(manager) = &mut self.sockmap_manager {
                manager.register_pair(client_fd, target_fd)?;
                info!("已注册到 sockmap: {} ↔ {}", client_fd, target_fd);
            }
        }

        // 发送 Client Hello 到目标服务器
        target_stream.write_all(&client_hello_data).await?;

        // 数据转发
        if self.ebpf_enabled {
            // eBPF 模式：在内核空间转发，用户态只需等待关闭
            self.wait_for_connection_close(client_stream, target_stream).await?;
        } else {
            // 传统模式：用户态转发
            proxy_data(client_stream, target_stream, ...).await?;
        }

        Ok(())
    }

    async fn wait_for_connection_close(
        &self,
        client_stream: TcpStream,
        target_stream: TcpStream,
    ) -> Result<()> {
        // 监听 socket 关闭事件
        // 可以使用 tokio 的 AsyncRead::read() 返回 0 来检测
        let client_fd = client_stream.as_raw_fd();
        let target_fd = target_stream.as_raw_fd();

        // 等待任一 socket 关闭
        tokio::select! {
            _ = async {
                let mut buf = [0u8; 1];
                loop {
                    match client_stream.try_read(&mut buf) {
                        Ok(0) => break,  // 连接关闭
                        Ok(_) => continue,  // 不应该到这里（数据已被 eBPF 处理）
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            } => {}
            _ = async {
                let mut buf = [0u8; 1];
                loop {
                    match target_stream.try_read(&mut buf) {
                        Ok(0) => break,
                        Ok(_) => continue,
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            tokio::time::sleep(Duration::from_millis(100)).await;
                            continue;
                        }
                        Err(_) => break,
                    }
                }
            } => {}
        }

        // 清理 sockmap 注册
        if let Some(manager) = &mut self.sockmap_manager {
            manager.unregister_pair(client_fd, target_fd)?;
        }

        Ok(())
    }
}
```

## 5. 性能预期

### 5.1 延迟对比

| 场景 | 当前 (μs) | eBPF (μs) | 改进 |
|------|-----------|-----------|------|
| DNS 查询（缓存命中） | 1-10 | 0.1-0.5 | **10-20x** |
| 数据转发（每包） | 50-100 | 5-10 | **10x** |
| 连接建立 | 11,000 | 8,000 | **27%** |
| IP 过滤（拒绝） | 100 | 1-2 | **50-100x** |

### 5.2 吞吐量对比

| 模式 | 当前 (req/s) | eBPF (req/s) | 改进 |
|------|--------------|--------------|------|
| 直连 | 50,000 | 100,000-150,000 | **2-3x** |
| SOCKS5 | 30,000 | 60,000-90,000 | **2-3x** |

### 5.3 CPU 使用对比

| 负载 | 当前 CPU | eBPF CPU | 节省 |
|------|----------|----------|------|
| 10,000 req/s | 50% | 20-25% | **50-60%** |
| 50,000 req/s | 95% | 40-50% | **47-58%** |

### 5.4 并发连接数

| 指标 | 当前 | eBPF |
|------|------|------|
| 最大并发连接 | 10,000 | 100,000+ |
| 内存占用/连接 | ~30KB | ~10KB |

## 6. 实施路线图

### Phase 1: 基础 eBPF 集成 (2-3 周)

**目标**: 实现 sockmap 数据转发

- [ ] 搭建 Aya 开发环境
- [ ] 实现基础 sockmap 程序
- [ ] 集成到现有代码（兼容模式）
- [ ] 单元测试和集成测试
- [ ] 性能基准测试

**预期收益**:
- 吞吐量提升 50-100%
- 延迟降低 30-40%
- CPU 使用降低 40-50%

### Phase 2: eBPF DNS 缓存 (1-2 周)

**目标**: 替换 Mutex<LruCache> 为 eBPF Map

- [ ] 实现 eBPF LRU Hash Map
- [ ] 用户态和内核态同步
- [ ] 缓存失效策略
- [ ] 性能测试

**预期收益**:
- DNS 查询延迟降低 90%
- 消除 Mutex 锁竞争

### Phase 3: XDP IP 过滤 (1 周)

**目标**: 在网卡层实现 IP 白名单

- [ ] 实现 XDP 程序
- [ ] IP 白名单加载
- [ ] DDoS 防护（可选）
- [ ] 性能测试

**预期收益**:
- 拒绝连接 CPU 开销降低 99%
- 提升整体系统稳定性

### Phase 4: 流量统计优化 (1 周)

**目标**: 使用 eBPF Per-CPU Map 统计

- [ ] 实现流量统计 eBPF 程序
- [ ] 替换现有原子计数
- [ ] 监控面板集成
- [ ] 性能测试

**预期收益**:
- 统计开销降低 90%
- 更细粒度的流量分析

### Phase 5: 生产环境部署 (2 周)

**目标**: 完整的生产环境支持

- [ ] 配置选项（启用/禁用 eBPF）
- [ ] 优雅降级（eBPF 加载失败时）
- [ ] 监控和告警
- [ ] 文档和运维手册
- [ ] 压力测试

**预期收益**:
- 生产级稳定性
- 完整的可观测性

## 7. 风险和限制

### 7.1 系统要求

- **Linux 内核**: 5.7+ (推荐 5.10+)
  - Sockmap: 4.14+
  - XDP: 4.8+
  - Per-CPU Map: 3.18+
- **权限**: CAP_BPF 或 root (内核 5.8+)
- **架构**: x86_64, ARM64

### 7.2 已知限制

1. **非 Linux 系统不支持**
   - 需要保留传统实现作为 fallback
   - macOS/Windows 自动禁用 eBPF

2. **调试困难**
   - eBPF 程序错误难以定位
   - 需要良好的日志和监控

3. **内核版本差异**
   - 不同内核版本 eBPF 特性不同
   - 需要运行时检测和兼容

4. **学习曲线**
   - eBPF 编程需要内核知识
   - 团队需要培训

### 7.3 降级策略

```rust
// 自动检测并降级
pub fn new(config: Config) -> Result<Self> {
    let ebpf_mode = if config.enable_ebpf {
        match Self::init_ebpf() {
            Ok(ebpf) => {
                info!("eBPF 加速已启用");
                EbpfMode::Enabled(ebpf)
            }
            Err(e) => {
                warn!("eBPF 初始化失败: {}, 降级到传统模式", e);
                EbpfMode::Disabled
            }
        }
    } else {
        info!("eBPF 未启用");
        EbpfMode::Disabled
    };

    // ...
}
```

## 8. 配置选项

### 8.1 配置文件扩展

```json
{
  "listen_addr": "0.0.0.0:8443",
  "max_connections": 50000,

  "ebpf": {
    "enabled": true,
    "sockmap": {
      "enabled": true,
      "max_entries": 65536
    },
    "dns_cache": {
      "enabled": true,
      "max_entries": 10000
    },
    "xdp": {
      "enabled": false,
      "interface": "eth0"
    },
    "stats": {
      "enabled": true,
      "per_cpu": true
    }
  },

  "fallback_mode": "auto"
}
```

### 8.2 运行时控制

```bash
# 查看 eBPF 状态
curl http://localhost:9090/ebpf/status

# 响应示例
{
  "ebpf_enabled": true,
  "features": {
    "sockmap": "active",
    "dns_cache": "active",
    "xdp": "disabled",
    "stats": "active"
  },
  "kernel_version": "5.15.0",
  "maps": {
    "sockmap": {
      "entries": 1234,
      "max_entries": 65536
    },
    "dns_cache": {
      "entries": 987,
      "max_entries": 10000,
      "hit_rate": 0.9667
    }
  }
}
```

## 9. 监控和调试

### 9.1 eBPF 监控指标

```rust
pub struct EbpfMetrics {
    // Sockmap 统计
    pub sockmap_redirects: u64,      // 成功重定向次数
    pub sockmap_fallbacks: u64,      // 降级到用户态次数
    pub sockmap_errors: u64,         // 错误次数

    // DNS 缓存统计
    pub dns_cache_hits: u64,         // 缓存命中
    pub dns_cache_misses: u64,       // 缓存未命中
    pub dns_cache_evictions: u64,    // 缓存淘汰

    // XDP 统计
    pub xdp_packets_passed: u64,     // 通过的包
    pub xdp_packets_dropped: u64,    // 丢弃的包
    pub xdp_packets_aborted: u64,    // 异常的包
}
```

### 9.2 调试工具

```bash
# 查看加载的 eBPF 程序
bpftool prog list

# 查看 eBPF Map
bpftool map list
bpftool map dump id <map_id>

# 查看 eBPF 日志（需要 aya-log）
cat /sys/kernel/debug/tracing/trace_pipe | grep sni-proxy

# 性能分析
perf record -e bpf:* -a
perf script
```

## 10. 参考资料

### 10.1 eBPF 学习资源

- **官方文档**:
  - [eBPF 文档](https://ebpf.io/)
  - [Cilium eBPF 教程](https://docs.cilium.io/en/stable/bpf/)
  - [Linux 内核 BPF 文档](https://www.kernel.org/doc/html/latest/bpf/)

- **Aya 框架**:
  - [Aya Book](https://aya-rs.dev/book/)
  - [Aya GitHub](https://github.com/aya-rs/aya)
  - [Aya 示例](https://github.com/aya-rs/aya/tree/main/aya/examples)

- **Sockmap 相关**:
  - [Sockmap 介绍](https://lwn.net/Articles/731133/)
  - [BPF Socket Redirection](https://cilium.io/blog/2018/08/07/bpf-socket-redirection/)

### 10.2 性能优化案例

- **Cloudflare**: [用 eBPF 加速负载均衡](https://blog.cloudflare.com/cloudflare-architecture-and-how-bpf-eats-the-world/)
- **Cilium**: [Kubernetes 网络加速](https://cilium.io/blog/2018/04/17/why-is-the-kernel-community-replacing-iptables/)
- **Facebook**: [Katran - L4 负载均衡](https://github.com/facebookincubator/katran)

## 11. 总结

### 11.1 为什么选择 eBPF

1. **性能提升显著**
   - 吞吐量提升 2-3 倍
   - 延迟降低 30-80%
   - CPU 使用降低 40-60%

2. **扩展性提升**
   - 支持 10 倍以上并发连接
   - 内存占用降低

3. **架构优势**
   - 内核级加速，零上下文切换
   - 无锁并发，充分利用多核
   - 可编程性强，灵活扩展

4. **生产级稳定**
   - 被广泛应用（Cloudflare, Netflix, Google）
   - 内核级安全验证
   - 自动降级，兼容性好

### 11.2 实施建议

1. **渐进式部署**
   - 先实现 sockmap（核心收益）
   - 再实现 DNS 缓存
   - 最后实现 XDP 和其他优化

2. **保持兼容性**
   - 保留传统实现作为 fallback
   - 自动检测内核版本和特性
   - 配置化启用/禁用

3. **完善监控**
   - 详细的 eBPF 指标
   - 对比传统模式性能
   - 及时发现问题

4. **充分测试**
   - 单元测试
   - 集成测试
   - 压力测试
   - 长期稳定性测试

---

**下一步**: 开始实施 Phase 1 - 基础 eBPF 集成
