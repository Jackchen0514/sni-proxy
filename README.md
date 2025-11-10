# SNI 代理服务器

一个用 Rust 编写的支持域名白名单的 SNI (Server Name Indication) 代理服务器。

## 功能特性

- ✅ 解析 TLS Client Hello 中的 SNI 字段
- ✅ 基于域名白名单的访问控制
- ✅ 高性能异步 I/O (基于 Tokio)
- ✅ 支持从配置文件加载白名单
- ✅ 详细的日志记录

## 工作原理

1. 客户端发起 HTTPS 连接到代理服务器
2. 代理解析 TLS Client Hello 消息，提取 SNI 域名
3. 检查域名是否在白名单中
4. 如果在白名单中，建立到目标服务器的连接并转发流量
5. 如果不在白名单中，拒绝连接

## 安装

确保已安装 Rust 工具链 (推荐使用 rustup)。

```bash
# 克隆或创建项目
cd sni-proxy

# 构建项目
cargo build --release
```

## 使用方法

### 方法 1: 使用代码中的白名单

编辑 `src/main.rs` 中的白名单配置:

```rust
let whitelist = vec![
    "www.example.com".to_string(),
    "api.example.com".to_string(),
    "github.com".to_string(),
    // 添加更多域名
];
```

运行:

```bash
cargo run --release
```

### 方法 2: 使用配置文件

1. 创建或编辑 `config.json`:

```json
{
  "listen_addr": "0.0.0.0:8443",
  "max_connections": 10000,
  "whitelist": [
    "example.com",
    "*.example.com"
  ]
}
```

2. 使用配置文件运行:

```bash
# 将 main_with_config.rs 重命名为 main.rs 或直接编译
cargo run --release --bin sni-proxy config.json
```

## 配置说明

### config.json

- `listen_addr`: 代理服务器监听地址和端口 (默认: `0.0.0.0:8443`)
- `whitelist`: 允许访问的域名列表

### 环境变量

日志级别可以通过 `RUST_LOG` 环境变量控制:

```bash
# 显示详细日志
RUST_LOG=debug cargo run --release

# 只显示错误日志
RUST_LOG=error cargo run --release
```

## 客户端配置

客户端需要配置代理:

### 使用 curl

```bash
curl --proxy https://localhost:8443 https://www.example.com
```

### 使用 OpenSSL s_client

```bash
openssl s_client -connect localhost:8443 -servername www.example.com -proxy localhost:8443
```

### 浏览器配置

在浏览器中配置 HTTPS 代理为 `localhost:8443`

## 安全注意事项

⚠️ **重要提示**:

1. 这是一个透明代理，不会解密或检查 TLS 流量内容
2. 仅基于 SNI 进行域名过滤，无法防止 SNI 欺骗
3. 建议在受信任的网络环境中使用
4. 生产环境中应添加更多安全措施:
   - IP 白名单/黑名单
   - 速率限制
   - 连接超时
   - 详细的审计日志

## 性能优化

- 使用 `--release` 模式编译以获得最佳性能
- 根据需要调整 Tokio 运行时的工作线程数
- 考虑使用连接池来提高性能

## 开发和测试

运行测试:

```bash
cargo test
```

运行开发模式:

```bash
RUST_LOG=debug cargo run
```

## 故障排除

### 连接被拒绝

- 检查域名是否在白名单中
- 查看日志确认 SNI 解析是否成功
- 确认目标服务器端口 443 可访问

### 无法解析 SNI

- 确保客户端发送的是标准 TLS Client Hello
- 检查客户端是否支持 SNI
- 查看详细日志 (`RUST_LOG=debug`)

## 许可证

MIT License

## 贡献

欢迎提交 Issue 和 Pull Request!
