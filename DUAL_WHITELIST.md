# 双白名单功能说明

SNI 代理服务器现在支持双白名单功能，可以同时配置直连白名单和 SOCKS5 白名单，实现流量分流。

## 功能特性

### 直连白名单 (`whitelist`)
- 这些域名的流量将直接连接到目标服务器
- 不经过 SOCKS5 代理
- 适合不需要代理的网站

### SOCKS5 白名单 (`socks5_whitelist`)
- 这些域名的流量将通过 SOCKS5 代理连接
- 需要配置 SOCKS5 代理服务器
- 适合需要代理访问的网站

## 配置示例

### 完整配置（双白名单模式）

```json
{
  "listen_addr": "0.0.0.0:8443",
  "whitelist": [
    "www.google.com",
    "github.com",
    "*.github.io",
    "*.cloudflare.com"
  ],
  "socks5_whitelist": [
    "*.anthropic.com",
    "claude.ai",
    "*.openai.com",
    "chatgpt.com"
  ],
  "socks5": {
    "addr": "127.0.0.1:1080",
    "username": null,
    "password": null
  },
  "log": {
    "level": "info",
    "output": "both",
    "file_path": "logs/sni-proxy.log",
    "enable_rotation": true,
    "max_size_mb": 100,
    "max_backups": 5
  }
}
```

### 仅直连模式（兼容旧配置）

```json
{
  "listen_addr": "0.0.0.0:8443",
  "whitelist": [
    "www.google.com",
    "github.com",
    "*.github.io"
  ]
}
```

### 仅 SOCKS5 模式

```json
{
  "listen_addr": "0.0.0.0:8443",
  "whitelist": [],
  "socks5_whitelist": [
    "*.anthropic.com",
    "claude.ai"
  ],
  "socks5": {
    "addr": "127.0.0.1:1080"
  }
}
```

## 匹配逻辑

当客户端连接时，服务器按以下逻辑处理：

1. **解析 SNI**: 从 TLS Client Hello 中提取域名
2. **检查白名单**:
   - 如果配置了 SOCKS5 白名单：
     - 优先检查域名是否在 `socks5_whitelist` 中
       - ✓ 匹配 → 使用 SOCKS5 连接
     - 如果不匹配，检查是否在 `whitelist` 中
       - ✓ 匹配 → 直接连接
       - ✗ 不匹配 → 拒绝连接
   - 如果未配置 SOCKS5 白名单：
     - 仅检查 `whitelist`
       - ✓ 匹配 → 直接连接
       - ✗ 不匹配 → 拒绝连接

### 流程图

```
客户端连接
    ↓
解析 SNI 域名
    ↓
是否有 SOCKS5 白名单？
    ├─ 是 → 检查 SOCKS5 白名单
    │        ├─ 匹配 → 通过 SOCKS5 连接
    │        └─ 不匹配 → 检查直连白名单
    │                    ├─ 匹配 → 直接连接
    │                    └─ 不匹配 → 拒绝连接
    │
    └─ 否 → 检查直连白名单
             ├─ 匹配 → 直接连接
             └─ 不匹配 → 拒绝连接
```

## 使用场景

### 场景 1: 国内外网站分流

```json
{
  "whitelist": [
    "*.baidu.com",
    "*.taobao.com",
    "*.qq.com"
  ],
  "socks5_whitelist": [
    "*.google.com",
    "*.youtube.com",
    "*.facebook.com"
  ]
}
```

- 国内网站（baidu, taobao, qq）直连，速度快
- 国外网站（google, youtube, facebook）通过 SOCKS5 代理

### 场景 2: AI 服务分流

```json
{
  "whitelist": [
    "github.com",
    "*.github.io",
    "*.stackoverflow.com"
  ],
  "socks5_whitelist": [
    "*.anthropic.com",
    "claude.ai",
    "*.openai.com",
    "chatgpt.com"
  ]
}
```

- 开发网站（github, stackoverflow）直连
- AI 服务（Claude, ChatGPT）通过代理

### 场景 3: 企业网络分流

```json
{
  "whitelist": [
    "*.company.com",
    "*.internal.local"
  ],
  "socks5_whitelist": [
    "*.cloud-provider.com",
    "*.external-api.com"
  ]
}
```

- 内网域名直连
- 外部云服务通过代理（安全审计、流量监控）

## 日志输出

### 启动日志

```
[2025-11-25 02:33:17.283] INFO  加载了 4 个直连白名单域名
[2025-11-25 02:33:17.283] INFO    [直连 1] www.google.com
[2025-11-25 02:33:17.283] INFO    [直连 2] github.com
[2025-11-25 02:33:17.283] INFO    [直连 3] *.github.io
[2025-11-25 02:33:17.283] INFO    [直连 4] *.cloudflare.com
[2025-11-25 02:33:17.283] INFO  加载了 4 个 SOCKS5 白名单域名
[2025-11-25 02:33:17.283] INFO    [SOCKS5 1] *.anthropic.com
[2025-11-25 02:33:17.283] INFO    [SOCKS5 2] claude.ai
[2025-11-25 02:33:17.283] INFO    [SOCKS5 3] *.openai.com
[2025-11-25 02:33:17.283] INFO    [SOCKS5 4] chatgpt.com
```

### 连接日志

```
# 匹配直连白名单
[INFO] 域名 github.com 匹配直连白名单

# 匹配 SOCKS5 白名单
[INFO] 域名 claude.ai 匹配 SOCKS5 白名单
[INFO] 通过 SOCKS5 连接到 claude.ai:443

# 不在任何白名单
[WARN] 域名 unknown.com 不在任何白名单中，拒绝连接
```

## 配置验证

### 常见错误

#### 1. 配置了 SOCKS5 白名单但未配置 SOCKS5 服务器

```json
{
  "whitelist": ["..."],
  "socks5_whitelist": ["*.anthropic.com"]
  // 缺少 "socks5" 配置
}
```

**日志警告**:
```
[WARN] 配置了 SOCKS5 白名单但未配置 SOCKS5 代理服务器！
[WARN] SOCKS5 白名单将无法生效，请检查配置文件
```

#### 2. SOCKS5 地址格式错误

```json
{
  "socks5": {
    "addr": "localhost:1080"  // 错误：应该使用 127.0.0.1
  }
}
```

**错误信息**: `无效的 SOCKS5 代理地址`

## 性能考虑

1. **白名单匹配**:
   - 精确匹配: O(1) - 使用 HashSet
   - 通配符匹配: O(n) - 已按长度排序优化

2. **优先级**:
   - SOCKS5 白名单优先于直连白名单
   - 如果域名同时在两个白名单中，将使用 SOCKS5

3. **建议**:
   - 常用域名使用精确匹配
   - 少量子域名才使用通配符
   - SOCKS5 白名单不宜过大（影响匹配性能）

## 兼容性

- ✓ 向后兼容旧配置（仅 `whitelist`）
- ✓ 支持通配符匹配（`*.example.com`）
- ✓ 支持混合模式（精确 + 通配符）
- ✓ 空白名单支持（仅 SOCKS5 或仅直连）

## 运行示例

```bash
# 使用双白名单配置
./sni-proxy config-dual-whitelist.json

# 使用仅直连配置
./sni-proxy config.json

# 查看日志
tail -f logs/sni-proxy.log | grep "匹配"
```

## 故障排查

### 问题: 域名应该走 SOCKS5 但实际直连了

**检查**:
1. 确认域名在 `socks5_whitelist` 中
2. 确认 SOCKS5 配置正确
3. 查看日志确认匹配结果

### 问题: 所有流量都被拒绝

**检查**:
1. 确认至少配置了一个白名单
2. 检查域名格式（通配符语法）
3. 查看日志中的域名提取结果

### 问题: SOCKS5 连接失败

**检查**:
1. SOCKS5 服务器是否运行
2. 地址和端口是否正确
3. 认证信息是否正确（如果需要）
