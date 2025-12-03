# TCP Fast Open (TFO) 优化指南

## 🚀 什么是 TCP Fast Open？

TCP Fast Open (TFO) 是一个 TCP 扩展（RFC 7413），允许在 TCP 三次握手期间传输数据，**节省 1 个 RTT（往返时间）**。

### 传统 TCP 连接

```
客户端                           服务器
  |                                |
  |-------- SYN ---------------->  |  RTT 1
  |<------- SYN-ACK ------------  |
  |-------- ACK ---------------->  |
  |                                |
  |-------- DATA --------------->  |  RTT 2 ← 首次数据传输
  |<------- DATA ---------------  |
```

**总延迟**: 2 RTT

### TCP Fast Open

```
客户端                           服务器
  |                                |
  |--- SYN + Cookie + DATA ---->  |  RTT 1 ← 数据已发送！
  |<-- SYN-ACK + DATA ----------  |
  |--- ACK --------------------->  |
```

**总延迟**: 1 RTT
**节省**: 1 RTT (通常 **20-200ms**)

---

## 📊 性能提升

### 延迟降低

| 场景 | 无 TFO | 有 TFO | 改善 |
|------|--------|--------|------|
| 本地网络 (RTT=1ms) | 2ms | 1ms | **-50%** |
| 国内网络 (RTT=20ms) | 40ms | 20ms | **-50%** |
| 跨国网络 (RTT=100ms) | 200ms | 100ms | **-50%** |
| 卫星网络 (RTT=500ms) | 1000ms | 500ms | **-50%** |

### 实际收益

**流媒体场景**（Netflix/Disney+）：
- 初始连接延迟：**-50~200ms**
- 首屏显示时间：**-100~300ms**
- 用户感知：**明显更快**

**短连接场景**（API 请求）：
- 每次请求：**-1 RTT**
- 高频场景收益更大

---

## 🔧 实现细节

### 服务端模式

sni-proxy 监听 socket 启用 TFO：

```rust
// 在 server.rs 中
const TCP_FASTOPEN: libc::c_int = 23;
let queue_len: libc::c_int = 256; // TFO 队列长度

libc::setsockopt(
    fd,
    libc::IPPROTO_TCP,
    TCP_FASTOPEN,
    &queue_len as *const _ as *const libc::c_void,
    std::mem::size_of_val(&queue_len) as libc::socklen_t,
);
```

**启动日志**：
```
✅ TCP Fast Open 已启用（服务端模式，队列: 256）
```

### 客户端模式

连接到目标服务器时启用 TFO：

```rust
// 在 proxy.rs 中
const TCP_FASTOPEN_CONNECT: libc::c_int = 30;
let enable: libc::c_int = 1;

libc::setsockopt(
    fd,
    libc::IPPROTO_TCP,
    TCP_FASTOPEN_CONNECT,
    &enable as *const _ as *const libc::c_void,
    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
);
```

**连接日志**：
```
✅ TCP Fast Open 已启用（客户端模式）
```

---

## 🖥️ 系统要求

### Linux 内核版本

| 功能 | 最低版本 | 推荐版本 |
|------|---------|---------|
| TFO 服务端 | **3.7+** | 4.11+ |
| TFO 客户端 | **3.13+** | 4.11+ |
| TFO 全功能 | 3.13+ | **5.4+** |

### 检查系统支持

```bash
# 检查内核版本
uname -r

# 检查 TFO 配置
cat /proc/sys/net/ipv4/tcp_fastopen
```

**tcp_fastopen 值说明**：
- `0`: 禁用
- `1`: 仅客户端
- `2`: 仅服务端
- `3`: 客户端 + 服务端（**推荐**）

---

## ⚙️ 系统配置

### 启用 TCP Fast Open

#### 临时启用（重启后失效）

```bash
# 启用客户端 + 服务端
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

#### 永久启用

```bash
# 编辑 /etc/sysctl.conf
sudo tee -a /etc/sysctl.conf <<EOF
# TCP Fast Open
net.ipv4.tcp_fastopen = 3
EOF

# 应用配置
sudo sysctl -p
```

### 验证配置

```bash
# 检查是否生效
sysctl net.ipv4.tcp_fastopen

# 预期输出
net.ipv4.tcp_fastopen = 3
```

---

## 🧪 测试 TCP Fast Open

### 1. 检查服务端 TFO

```bash
# 启动 sni-proxy
./sni-proxy config.json

# 查看日志，应该看到：
# ✅ TCP Fast Open 已启用（服务端模式，队列: 256）
```

### 2. 使用 tcpdump 抓包验证

```bash
# 抓包
sudo tcpdump -i lo port 8443 -w tfo-test.pcap

# 客户端连接
curl --proxy socks5h://127.0.0.1:8443 https://www.google.com

# 分析抓包（查找 TFO Cookie）
tcpdump -r tfo-test.pcap -X | grep -A 5 "TCP Fastopen"
```

### 3. 使用 ss 命令查看

```bash
# 查看 TFO 统计
ss -tnie | grep -i fastopen

# 查看 TFO Cookie
cat /proc/net/netstat | grep TcpExt | awk '{print $87, $88, $89}'
```

---

## 📈 性能监控

### TFO 统计信息

```bash
# 查看系统级 TFO 统计
netstat -s | grep -i "fast open"

# 预期输出：
# TCPFastOpenActive: 123        # 客户端使用 TFO 次数
# TCPFastOpenPassive: 456       # 服务端接受 TFO 次数
# TCPFastOpenPassiveFail: 0     # 服务端 TFO 失败
# TCPFastOpenListenOverflow: 0  # TFO 队列溢出
# TCPFastOpenCookieReqd: 789    # Cookie 请求数
```

### 关键指标

| 指标 | 说明 | 健康值 |
|------|------|--------|
| `TCPFastOpenActive` | 客户端 TFO 成功 | 递增 |
| `TCPFastOpenPassive` | 服务端 TFO 成功 | 递增 |
| `TCPFastOpenPassiveFail` | 服务端失败 | = 0 |
| `TCPFastOpenListenOverflow` | 队列溢出 | = 0 |

---

## ⚠️ 注意事项

### 1. Cookie 机制

TFO 使用 Cookie 防止 SYN Flood 攻击：
- 首次连接：获取 Cookie
- 后续连接：使用 Cookie + 携带数据

**首次连接仍需 2 RTT**，但后续连接只需 1 RTT。

### 2. 兼容性

#### 客户端支持

| 客户端 | TFO 支持 | 说明 |
|--------|---------|------|
| Chrome 61+ | ✅ | 默认启用 |
| Firefox 58+ | ✅ | 需配置 |
| curl 7.49+ | ✅ | 需 `--tcp-fastopen` |
| 大部分浏览器 | ✅ | 现代浏览器支持 |

#### 服务端支持

| 服务 | TFO 支持 |
|------|---------|
| Nginx 1.5.8+ | ✅ |
| Apache 2.4.17+ | ✅ |
| sni-proxy | ✅ ← 本项目 |

### 3. 网络环境

某些网络环境可能阻止 TFO：
- 部分防火墙/NAT 设备
- 某些 ISP 网络
- 旧的网络设备

**sni-proxy 会自动回退**到标准 TCP，不影响连接。

---

## 🔍 故障排查

### 问题 1: TFO 未启用

**症状**：
```
⚠️ TCP Fast Open 启用失败（系统可能不支持）
```

**解决方案**：
```bash
# 1. 检查内核版本
uname -r  # 需要 >= 3.7

# 2. 检查系统配置
cat /proc/sys/net/ipv4/tcp_fastopen

# 3. 启用 TFO
sudo sysctl -w net.ipv4.tcp_fastopen=3
```

### 问题 2: 队列溢出

**症状**：
```bash
netstat -s | grep TCPFastOpenListenOverflow
# TCPFastOpenListenOverflow: 1234  # 不为 0
```

**解决方案**：
```rust
// 增大队列大小（在 server.rs 中）
let queue_len: libc::c_int = 512; // 从 256 增加到 512
```

### 问题 3: Cookie 验证失败

**症状**：
```bash
netstat -s | grep TCPFastOpenPassiveFail
# TCPFastOpenPassiveFail: 456  # 很高
```

**解决方案**：
```bash
# 可能是 Cookie 过期，调整超时
# (通常系统自动处理，无需手动干预)
```

---

## 📚 进阶配置

### 1. Cookie 超时调整

```bash
# Cookie 有效期（秒）
sudo sysctl -w net.ipv4.tcp_fastopen_key_expires=3600
```

### 2. TFO 黑名单

某些目标服务器不支持 TFO，可以配置黑名单：

```bash
# 禁用到特定 IP 的 TFO
ip route add <target-ip> via <gateway> advmss 1460 fastopen_no_cookie
```

### 3. TFO Cookie 密钥轮换

```bash
# 定期轮换 Cookie 密钥（增强安全性）
sudo sysctl -w net.ipv4.tcp_fastopen_blackhole_timeout=600
```

---

## 🎯 最佳实践

### 1. 生产环境部署

```bash
# /etc/sysctl.conf
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fastopen_key_expires = 3600

# 应用配置
sudo sysctl -p
```

### 2. 监控和告警

```bash
#!/bin/bash
# tfo-monitor.sh

# 获取 TFO 统计
active=$(netstat -s | grep TCPFastOpenActive | awk '{print $2}')
passive=$(netstat -s | grep TCPFastOpenPassive | awk '{print $2}')
overflow=$(netstat -s | grep TCPFastOpenListenOverflow | awk '{print $2}')

# 检查队列溢出
if [ "$overflow" -gt 100 ]; then
    echo "WARNING: TFO queue overflow detected: $overflow"
    # 发送告警
fi

# 记录统计
echo "$(date) TFO Active: $active, Passive: $passive, Overflow: $overflow"
```

### 3. 性能基准测试

```bash
# 测试 TFO 前后延迟差异
# 1. 禁用 TFO
sudo sysctl -w net.ipv4.tcp_fastopen=0
time curl --proxy socks5h://127.0.0.1:8443 https://www.google.com

# 2. 启用 TFO
sudo sysctl -w net.ipv4.tcp_fastopen=3
time curl --tcp-fastopen --proxy socks5h://127.0.0.1:8443 https://www.google.com

# 对比结果
```

---

## 📖 参考资料

### RFC 和标准
- [RFC 7413 - TCP Fast Open](https://tools.ietf.org/html/rfc7413)
- [Linux TCP Fast Open Documentation](https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt)

### 技术文章
- [Cloudflare: TCP Fast Open](https://blog.cloudflare.com/tcp-fast-open/)
- [Google: TCP Fast Open - 加速网络](https://blog.chromium.org/2014/05/tcp-fast-open-secure-and-reliable.html)

### 工具和库
- [tcpdump - 网络抓包](https://www.tcpdump.org/)
- [Wireshark - 分析 TFO](https://www.wireshark.org/)

---

## 🔐 安全性

### TFO 安全机制

1. **Cookie 验证**：防止 SYN Flood 攻击
2. **时间戳**：防止重放攻击
3. **序列号**：保证数据完整性

### 潜在风险

| 风险 | 缓解措施 |
|------|---------|
| SYN Flood | Cookie 验证 |
| 重放攻击 | 时间戳检查 |
| Cookie 猜测 | 密钥轮换 |

TFO 的安全性已经过充分验证，可以放心在生产环境使用。

---

## 📊 总结

### 收益

- ✅ **延迟降低 50%**（首次数据传输）
- ✅ **用户体验提升**（特别是流媒体）
- ✅ **系统开销极小**（仅多占用少量内存）
- ✅ **向后兼容**（不支持时自动回退）

### 适用场景

**强烈推荐**：
- 流媒体服务（Netflix、Disney+）
- 在线视频会议
- 实时游戏
- API 服务（高频短连接）

**一般推荐**：
- Web 浏览
- 文件下载（长连接收益小）

### 实施难度

- **配置难度**: ⭐ (极简单)
- **维护成本**: ⭐ (几乎无)
- **收益产出**: ⭐⭐⭐⭐⭐ (显著)

**强烈建议在生产环境启用 TCP Fast Open！**

---

**最后更新**: 2025-12-03
**版本**: 1.0.0
