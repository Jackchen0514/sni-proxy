# SNI 代理服务器

一个用 Rust 编写的高性能 SNI (Server Name Indication) 代理服务器：不解密 TLS 流量，只读取 ClientHello 里的 SNI 字段做域名白名单过滤和转发。

当前版本 **v2.1.1**。

## 功能特性

- ✅ 解析 TLS ClientHello 中的 SNI 字段（支持跨多个 TCP 包的大 ClientHello）
- ✅ 直连 / SOCKS5 双白名单：不同域名可以分别走直连或走 SOCKS5 出口
- ✅ IP 白名单（可选）：支持单个 IP 或 CIDR 网段，IPv4/IPv6 都支持
- ✅ IP 流量统计、域名-IP 映射追踪（可选，可持久化到文件）
- ✅ 高性能异步 I/O（基于 Tokio），线程数/连接数/缓冲区按 CPU 核心数自适应
- ✅ 优雅关闭（SIGTERM/SIGINT/SIGQUIT，等待活跃连接处理完再退出）
- ✅ 目标 IP 连接故障转移（DNS 解析出多个 IP 时会尝试多个候选，而不是只连第一个）
- ✅ 可配置的结构化日志（支持文件输出、日志轮转）

## 工作原理

这是一个**透明的 TLS 直通代理**，不是 HTTP CONNECT 代理，客户端不需要（也不能）像配置普通代理那样配置它：

1. 客户端的 TLS 连接（TCP SYN）到达代理监听的地址和端口
2. 代理读取 ClientHello，提取 SNI 域名
3. 依次检查是否匹配 SOCKS5 白名单 → 直连白名单 → 都不匹配则拒绝连接
   （如果配置了 IP 白名单，还会先检查客户端源 IP 是否在白名单内）
4. 匹配上白名单后，代理连接真正的目标服务器（直连或经 SOCKS5），把 ClientHello 转发过去，之后原样双向转发字节流

因为代理不解密流量，也看不到、改不了 TLS 内容之外的任何东西，只能基于 SNI 做域名级别的放行/拒绝。

要让流量真正走到代理这里，通常是下面两种方式之一：
- **DNS 方式**：把需要代理的域名解析到代理服务器的 IP（自建 DNS / hosts / 路由器 DNS 劫持）
- **路由/防火墙方式**：用 iptables/nftables 之类的规则把目标端口 443 的流量重定向到代理监听的端口

## 快速开始

### 下载预编译二进制（推荐）

从 [Releases](https://github.com/Jackchen0514/sni-proxy/releases) 页面下载对应平台的压缩包并解压，目前提供：

- Linux x86_64 / ARM64（`*.tar.gz`）
- macOS ARM64（`*.tar.gz`）
- Windows x86_64（`*.zip`）

建议用 `SHA256SUMS` 校验一下下载文件的完整性。

### 从源码构建

确保已安装 Rust 工具链（推荐用 rustup）：

```bash
cargo build --release
# 二进制产物在 target/release/sni-proxy
```

## 使用方法

准备一份配置文件（默认读取当前目录下的 `config.json`，也可以传路径作为第一个参数）：

```bash
# 使用默认的 ./config.json
./sni-proxy

# 指定配置文件路径
./sni-proxy /etc/sni-proxy/config.json

# 从源码运行（注意 -- 后面才是传给程序的参数）
cargo run --release -- config.json
```

停止服务：`Ctrl+C`（SIGINT）或 `kill <pid>`（SIGTERM）都会触发优雅关闭——停止接受新连接，等现有连接处理完（最多等 30 秒）再退出。

## 配置文件说明（config.json）

最小可用配置：

```json
{
  "listen_addr": "0.0.0.0:8443",
  "whitelist": [
    "example.com",
    "*.example.com"
  ]
}
```

完整字段参考 `config.example.json`：

```json
{
  "listen_addr": "0.0.0.0:8443",
  "whitelist": [
    "www.google.com",
    "github.com",
    "*.github.io",
    "*.anthropic.com",
    "claude.ai"
  ],
  "ip_whitelist": [
    "127.0.0.1",
    "192.168.1.0/24",
    "10.0.0.0/8",
    "::1",
    "2001:db8::/32"
  ],
  "log": {
    "level": "info",
    "output": "both",
    "file_path": "logs/sni-proxy.log",
    "enable_rotation": true,
    "max_size_mb": 100,
    "max_backups": 5,
    "show_timestamp": true,
    "show_module": true,
    "use_color": true
  },
  "socks5": {
    "addr": "127.0.0.1:1080",
    "username": null,
    "password": null
  }
}
```

### 字段说明

| 字段 | 必填 | 说明 |
|---|---|---|
| `listen_addr` | 是 | 监听地址和端口，如 `0.0.0.0:8443` |
| `whitelist` | 是* | 直连白名单域名列表 |
| `socks5_whitelist` | 否 | SOCKS5 白名单域名列表（命中的域名走 `socks5` 配置的出口） |
| `ip_whitelist` | 否 | 客户端源 IP 白名单，留空表示不限制来源 IP |
| `ip_traffic_tracking` | 否 | IP 流量统计配置，见下 |
| `domain_ip_tracking` | 否 | 域名-IP 映射追踪配置，见下 |
| `socks5` | 否 | SOCKS5 出口代理配置（`socks5_whitelist` 非空时必须配置） |
| `log` | 否 | 日志配置，见下 |

\* `whitelist` 和 `socks5_whitelist` 不能同时为空。

**域名匹配规则**（`whitelist`/`socks5_whitelist` 通用）：
- `"example.com"` — 精确匹配
- `"*.example.com"` — 匹配 `example.com` 的所有子域名（不含 `example.com` 本身）
- `"*"` — 匹配所有域名

**`ip_whitelist` 格式**：单个 IP（`"192.168.1.1"`、`"::1"`）或 CIDR 网段（`"10.0.0.0/8"`、`"2001:db8::/32"`），IPv4/IPv6 均可。

**`ip_traffic_tracking`**（记录每个白名单内 IP 的连接数/上传/下载流量）：

```json
{
  "enabled": true,
  "max_tracked_ips": 1000,
  "output_file": "stats/ip-traffic.txt",
  "persistence_file": "stats/ip-traffic.json"
}
```
- `max_tracked_ips`：LRU 淘汰上限，默认 1000
- `output_file`：可读的统计摘要，每分钟覆盖写入一次
- `persistence_file`：JSON 格式，每 5 分钟保存一次，重启后自动加载恢复

**`domain_ip_tracking`**（记录每个域名解析到过哪些 IP，SOCKS5 流量记为占位标记）：

```json
{
  "enabled": true,
  "output_file": "stats/domain-ip.txt"
}
```

**`log`**：
- `level`：`off` / `error` / `warn` / `info` / `debug` / `trace`，默认 `info`
- `output`：`stdout` / `file` / `both`，默认 `stdout`
- `file_path`：输出到文件时的路径，默认 `logs/sni-proxy.log`
- `enable_rotation`：是否按大小轮转日志文件，配合 `max_size_mb`（默认 100）、`max_backups`（默认 5）

> 注意：日志级别由 `config.json` 里的 `log.level` 控制，运行时**不读取** `RUST_LOG` 环境变量。改日志级别直接改配置文件即可。

## 测试连接

由于是 TLS 直通而非 HTTP CONNECT 代理，测试时不能用 `curl --proxy` 或 `openssl s_client -proxy`，而是要让 SNI 指向目标域名、TCP 连接指向代理：

```bash
# openssl：直接连代理的地址和端口，用 -servername 指定 SNI
openssl s_client -connect <代理IP>:8443 -servername www.example.com

# curl：用 --connect-to 把对目标域名 443 端口的连接重定向到代理，SNI/Host 保持不变
curl --connect-to www.example.com:443:<代理IP>:8443 https://www.example.com/
```

## 安全注意事项

⚠️ **重要提示**:

1. 这是透明代理，不解密也不检查 TLS 流量内容，只能做域名级别的过滤
2. 仅基于 SNI 过滤，无法防止客户端伪造/剥离 SNI（TLS 1.3 ECH 等场景下也无法工作）
3. 建议配合 `ip_whitelist` 限制允许连接的客户端来源
4. 生产环境建议结合防火墙做速率限制，并开启日志/统计追踪功能便于审计

## 开发和测试

```bash
cargo test              # 运行单元测试
cargo run -- config.json   # 开发模式运行（默认 info 级别，改配置文件里的 log.level 看更详细日志）
```

## 故障排除

### 连接被拒绝

- 检查域名是否在 `whitelist`/`socks5_whitelist` 里，检查客户端源 IP 是否在 `ip_whitelist` 里（如果配置了的话）
- 把 `log.level` 调成 `debug` 看具体是哪一步被拒绝的

### 无法解析 SNI

- 确认客户端发的是标准 TLS ClientHello（比如用上面的 `openssl s_client` 命令直接测）
- `debug` 级别日志里会打印 SNI 解析失败/超时的具体原因

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request!
