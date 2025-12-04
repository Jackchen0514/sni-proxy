# eBPF 内核态程序

本目录包含 SNI-Proxy 的 eBPF 内核态程序，用于提供高性能的数据包处理。

## 概述

eBPF (Extended Berkeley Packet Filter) 程序运行在 Linux 内核空间，可以安全高效地处理网络数据包。

### 功能

1. **Sockmap 数据转发**
   - 内核级零拷贝数据转发
   - 延迟降低 80-90%
   - 吞吐量提升 2-3 倍

2. **DNS 缓存**
   - 使用 eBPF LRU Hash Map
   - 无锁并发访问
   - 查询延迟 <1μs

3. **流量统计**
   - Per-CPU Map 零开销统计
   - 每个 CPU 独立计数
   - 无原子操作竞争

4. **XDP IP 过滤**
   - 网卡驱动层过滤
   - 早期丢包，极低延迟
   - DDoS 防护

## 系统要求

### 最低要求
- Linux 内核: **4.14+** (Sockmap)
- Linux 内核: **4.8+** (XDP)
- 架构: x86_64, ARM64
- 权限: root 或 CAP_BPF (内核 5.8+)

### 推荐配置
- Linux 内核: **5.10+**
- Rust: 1.70+
- bpf-linker: 最新版

### 检查系统支持

```bash
# 检查内核版本
uname -r

# 检查 eBPF 文件系统
ls /sys/fs/bpf

# 检查 BPF 系统调用
cat /proc/sys/kernel/unprivileged_bpf_disabled
# 0 = 启用, 1 = 禁用
```

## 安装依赖

### 1. 安装 Rust（如果还没有）

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source $HOME/.cargo/env
```

### 2. 安装 bpf-linker

```bash
cargo install bpf-linker
```

### 3. 安装开发工具（Ubuntu/Debian）

```bash
sudo apt-get update
sudo apt-get install -y \
    clang \
    llvm \
    libelf-dev \
    linux-headers-$(uname -r) \
    build-essential
```

### 4. 安装开发工具（Fedora/RHEL）

```bash
sudo dnf install -y \
    clang \
    llvm \
    elfutils-libelf-devel \
    kernel-devel \
    make
```

## 构建

### 方法 1: 使用构建脚本（推荐）

```bash
cd ..  # 回到项目根目录
./scripts/build-ebpf.sh
```

### 方法 2: 使用 Makefile

```bash
cd ..  # 回到项目根目录
make build-ebpf
```

### 方法 3: 手动构建

```bash
# 设置目标架构
export CARGO_TARGET=bpfel-unknown-none  # 小端
# 或
export CARGO_TARGET=bpfeb-unknown-none  # 大端

# 编译
cargo build --release --target=$CARGO_TARGET

# 编译产物位置
ls -lh ../target/$CARGO_TARGET/release/sni-proxy
```

## 程序结构

### Map 定义

```rust
// Socket Hash Map - 存储 socket fd
SOCK_MAP: SockHash<u64>

// 连接映射 - 建立双向关系
CONNECTION_MAP: HashMap<u64, u64>

// DNS 缓存 - LRU 自动淘汰
DNS_CACHE: LruHashMap<u64, DnsRecord>

// 流量统计 - Per-CPU
TRAFFIC_STATS: PerCpuArray<u64>

// 连接统计
CONNECTION_STATS: HashMap<u64, ConnectionStats>

// IP 白名单
IP_WHITELIST: HashMap<u32, u8>

// 配置参数
CONFIG: Array<u32>
```

### 程序类型

1. **SK_MSG (`redirect_msg`)**
   - 类型: `BPF_PROG_TYPE_SK_MSG`
   - 功能: Socket 消息重定向
   - 附加点: Sockmap

2. **XDP (`xdp_ip_filter`)**
   - 类型: `BPF_PROG_TYPE_XDP`
   - 功能: IP 白名单过滤
   - 附加点: 网络接口

## 数据结构

### DnsRecord

```rust
struct DnsRecord {
    ip_type: u8,        // 4=IPv4, 6=IPv6
    ipv4: [u8; 4],      // IPv4 地址
    ipv6: [u8; 16],     // IPv6 地址
    timestamp: u64,     // 时间戳
    ttl: u32,           // TTL
}
```

### ConnectionStats

```rust
struct ConnectionStats {
    bytes_sent: u64,        // 发送字节
    bytes_received: u64,    // 接收字节
    packets_sent: u64,      // 发送包数
    packets_received: u64,  // 接收包数
    start_time: u64,        // 开始时间
}
```

## 工作流程

### Sockmap 数据转发

```
1. 客户端发送数据 → socket A
2. 内核触发 SK_MSG 程序
3. 程序获取 socket A 的 cookie
4. 在 CONNECTION_MAP 中查找对端 socket B
5. 直接重定向数据到 socket B（零拷贝）
6. 更新流量统计
```

### XDP IP 过滤

```
1. 数据包到达网卡
2. 网卡驱动触发 XDP 程序
3. 解析以太网头和 IP 头
4. 检查源 IP 是否在白名单
5. 在白名单 → XDP_PASS（继续处理）
6. 不在白名单 → XDP_DROP（直接丢弃）
```

## 调试

### 查看加载的 eBPF 程序

```bash
# 列出所有 eBPF 程序
sudo bpftool prog list

# 查看特定程序
sudo bpftool prog show id <id>

# 查看程序的字节码
sudo bpftool prog dump xlated id <id>
```

### 查看 eBPF Map

```bash
# 列出所有 Map
sudo bpftool map list

# 查看 Map 内容
sudo bpftool map dump id <id>

# 更新 Map
sudo bpftool map update id <id> key <key> value <value>
```

### 查看内核日志

```bash
# 实时查看 eBPF 日志
sudo cat /sys/kernel/debug/tracing/trace_pipe | grep sni-proxy

# 查看内核环缓冲区
sudo dmesg | grep -i bpf
```

### 常见问题

#### 1. 编译错误: "bpf-linker not found"

```bash
# 安装 bpf-linker
cargo install bpf-linker
```

#### 2. 加载错误: "Operation not permitted"

```bash
# 需要 root 权限
sudo ./target/release/sni-proxy

# 或添加 capabilities
sudo setcap cap_bpf,cap_net_admin+ep ./target/release/sni-proxy
```

#### 3. 加载错误: "Invalid argument"

可能原因：
- 内核版本过低
- eBPF 功能未启用
- 程序字节码有问题

检查内核配置：
```bash
grep CONFIG_BPF /boot/config-$(uname -r)
```

应该看到：
```
CONFIG_BPF=y
CONFIG_BPF_SYSCALL=y
CONFIG_BPF_JIT=y
```

## 性能优化

### 编译优化

```toml
[profile.release]
lto = true
opt-level = 3
codegen-units = 1
```

### Map 大小调优

根据实际需求调整 Map 大小：

```rust
// 高并发场景
SOCK_MAP: SockHash::with_max_entries(1000000, 0)

// 低内存场景
DNS_CACHE: LruHashMap::with_max_entries(1000, 0)
```

### Per-CPU Map 优化

使用 Per-CPU Map 避免缓存行竞争：

```rust
// 不好：全局计数器，原子操作
COUNTER: AtomicU64

// 好：Per-CPU 计数，无竞争
STATS: PerCpuArray<u64>
```

## 安全考虑

1. **验证器检查**
   - eBPF 程序必须通过内核验证器
   - 不允许无限循环
   - 不允许访问任意内存

2. **资源限制**
   - Map 大小有上限
   - 指令数有限制
   - 栈大小限制为 512 字节

3. **权限要求**
   - 需要 root 或 CAP_BPF
   - 生产环境建议使用 capabilities

## 参考资料

- [eBPF 官方文档](https://ebpf.io/)
- [Aya 框架文档](https://aya-rs.dev/book/)
- [Linux BPF 文档](https://www.kernel.org/doc/html/latest/bpf/)
- [BPF 性能工具](http://www.brendangregg.com/ebpf.html)

## 许可证

同主项目许可证。
