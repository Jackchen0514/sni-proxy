# 日志配置说明

SNI 代理服务器现在支持完整的日志配置，包括文件输出和日志轮转功能。

## 配置文件格式

在 `config.json` 中添加 `log` 配置项：

```json
{
  "listen_addr": "0.0.0.0:8443",
  "whitelist": ["..."],
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
  }
}
```

## 配置项说明

### level (字符串，可选)
日志级别，支持以下值：
- `off` - 关闭所有日志
- `error` - 仅显示错误
- `warn` - 显示警告和错误
- `info` - 显示信息、警告和错误（默认）
- `debug` - 显示调试、信息、警告和错误
- `trace` - 显示所有日志

**默认值**: `"info"`

### output (字符串，可选)
日志输出目标：
- `stdout` - 仅输出到标准输出（终端）
- `file` - 仅输出到文件
- `both` - 同时输出到标准输出和文件

**默认值**: `"stdout"`

### file_path (字符串，可选)
日志文件路径。当 `output` 为 `file` 或 `both` 时需要指定。

**默认值**: `"logs/sni-proxy.log"`

### enable_rotation (布尔值，可选)
是否启用日志轮转。启用后，当日志文件达到指定大小时会自动创建新文件。

**默认值**: `false`

### max_size_mb (数字，可选)
单个日志文件的最大大小（单位：MB）。仅在启用日志轮转时生效。

**默认值**: `100`

### max_backups (数字，可选)
保留的日志文件备份数量。仅在启用日志轮转时生效。

**默认值**: `5`

**轮转规则**:
- 当前日志文件：`app.log`
- 第1个备份：`app.log.1`
- 第2个备份：`app.log.2`
- 第N个备份：`app.log.N`
- 超过 `max_backups` 的旧文件会被自动删除

### show_timestamp (布尔值，可选)
是否在日志中显示时间戳。

**默认值**: `true`

### show_module (布尔值，可选)
是否在日志中显示模块路径。

**默认值**: `true`

### use_color (布尔值，可选)
是否使用彩色输出（仅影响标准输出，文件输出始终不使用颜色）。

**默认值**: `true`

## 配置示例

### 示例 1: 仅输出到标准输出（开发环境）

```json
{
  "listen_addr": "127.0.0.1:8443",
  "whitelist": ["..."],
  "log": {
    "level": "debug",
    "output": "stdout"
  }
}
```

### 示例 2: 仅输出到文件（生产环境）

```json
{
  "listen_addr": "0.0.0.0:8443",
  "whitelist": ["..."],
  "log": {
    "level": "info",
    "output": "file",
    "file_path": "logs/sni-proxy.log",
    "enable_rotation": true,
    "max_size_mb": 100,
    "max_backups": 5,
    "show_timestamp": true,
    "show_module": true,
    "use_color": false
  }
}
```

### 示例 3: 同时输出到标准输出和文件（推荐）

```json
{
  "listen_addr": "0.0.0.0:8443",
  "whitelist": ["..."],
  "log": {
    "level": "info",
    "output": "both",
    "file_path": "logs/sni-proxy.log",
    "enable_rotation": true,
    "max_size_mb": 50,
    "max_backups": 3,
    "show_timestamp": true,
    "show_module": true,
    "use_color": true
  }
}
```

### 示例 4: 调试模式

```json
{
  "listen_addr": "127.0.0.1:8443",
  "whitelist": ["..."],
  "log": {
    "level": "debug",
    "output": "both",
    "file_path": "logs/debug.log",
    "enable_rotation": true,
    "max_size_mb": 10,
    "max_backups": 3
  }
}
```

## 日志输出格式

### 带时间戳和模块路径（默认）
```
[2025-11-25 02:10:18.160] INFO  [sni_proxy]  === SNI 代理服务器启动 ===
[2025-11-25 02:10:18.161] INFO  [sni_proxy::server]  SNI 代理服务器启动在 0.0.0.0:8443
```

### 简洁格式
```json
{
  "log": {
    "show_timestamp": false,
    "show_module": false
  }
}
```

输出：
```
INFO  === SNI 代理服务器启动 ===
INFO  SNI 代理服务器启动在 0.0.0.0:8443
```
  日志配置选项

  | 选项              | 类型      | 默认值                  | 说明                                         |
  |-----------------|---------|----------------------|--------------------------------------------|
  | level           | string  | "info"               | 日志级别: off, error, warn, info, debug, trace |
  | output          | string  | "stdout"             | 输出目标: stdout, file, both                   |
  | file_path       | string  | "logs/sni-proxy.log" | 日志文件路径                                     |
  | enable_rotation | boolean | false                | 是否启用日志轮转                                   |
  | max_size_mb     | number  | 100                  | 单个文件最大大小（MB）                               |
  | max_backups     | number  | 5                    | 保留的备份数量                                    |
  | show_timestamp  | boolean | true                 | 是否显示时间戳                                    |
  | show_module     | boolean | true                 | 是否显示模块路径                                   |
  | use_color       | boolean | true                 | 是否使用彩色输出                                   |

## 注意事项

1. **日志目录自动创建**: 如果日志文件路径中的目录不存在，会自动创建。

2. **权限问题**: 确保程序有权限在指定路径创建和写入文件。

3. **日志轮转性能**: 启用日志轮转时，每次写入都会检查文件大小。建议将 `max_size_mb` 设置为合理的值（50-100MB）。

4. **磁盘空间**: 注意监控磁盘空间，避免日志文件占满磁盘。可以通过调整 `max_size_mb` 和 `max_backups` 来控制总磁盘占用。

5. **彩色输出**: 终端支持 ANSI 颜色代码时，`use_color: true` 会使日志更易读。

## 日志级别建议

- **开发环境**: 使用 `debug` 级别，输出到标准输出或同时输出
- **测试环境**: 使用 `info` 级别，输出到文件
- **生产环境**: 使用 `info` 或 `warn` 级别，输出到文件并启用轮转
- **故障排查**: 临时调整为 `debug` 或 `trace` 级别

## 运行示例

```bash
# 使用默认配置文件（config.json）
./sni-proxy

# 使用指定配置文件
./sni-proxy config-production.json

# 使用调试配置
./sni-proxy config-debug.json
```

## 查看日志

```bash
# 实时查看日志
tail -f logs/sni-proxy.log

# 查看最近的错误
grep ERROR logs/sni-proxy.log

# 查看特定域名的日志
grep "github.com" logs/sni-proxy.log

# 查看所有日志文件
ls -lh logs/
```
