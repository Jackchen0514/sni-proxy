# eBPF 集成状态说明

## 当前实现概述

本项目已经完成了 eBPF 加速功能的**初步集成**，但还需要进一步开发才能真正加载 eBPF 程序到内核。

## 已完成的工作 ✅

### 1. eBPF 内核程序 (ebpf/src/main.rs)
- ✅ 编译成功，生成 2.2KB ELF 文件
- ✅ 定义了 7 个 eBPF Maps（SOCK_MAP, CONNECTION_MAP, DNS_CACHE等）
- ✅ 实现了 SK_MSG 程序（sockmap重定向）
- ✅ 实现了 XDP 程序（IP白名单过滤）

### 2. 用户空间框架 (src/ebpf/*)
- ✅ EbpfManager：统一管理所有 eBPF 组件
- ✅ SockmapManager：Socket对管理（占位实现）
- ✅ EbpfDnsCache：DNS缓存（占位实现）
- ✅ EbpfStats：流量统计（占位实现）
- ✅ XdpManager：XDP管理器（占位实现）

### 3. 主程序集成 (src/main.rs, src/server.rs)
- ✅ 配置文件支持（config-ebpf.json）
- ✅ SniProxy 集成 EbpfManager
- ✅ DNS 解析集成 eBPF 缓存查询
- ✅ 内核能力检测和优雅降级

### 4. eBPF 程序加载机制 (NEW!)
- ✅ 启用 aya 0.12 依赖
- ✅ 创建 build.rs 自动编译 eBPF 程序
- ✅ EbpfManager 使用 aya::Bpf::load() 加载程序
- ✅ 支持从嵌入字节码或文件系统加载

## 当前状态 ⚠️

### 可以运行，但 eBPF 未真正加载

当你运行 `sudo ./target/release/sni-proxy config-ebpf.json` 时：

**在 kernel 4.4.0 环境 (当前测试环境):**
```
[INFO] eBPF 系统能力: Kernel: 4.4.0, Sockmap: ✗, XDP: ✗, Per-CPU Map: ✓
[WARN] 系统不完全支持 eBPF 功能，将降级到传统模式
[WARN] 需要内核版本 >= 4.14，当前: 4.4.0
[INFO] ✅ eBPF 管理器初始化成功
```
- ✅ 检测到内核不支持，正确降级
- ✅ 不尝试加载 eBPF 程序
- ✅ 使用传统模式运行

**在 kernel 6.14.0 环境 (预期):**
```
[INFO] eBPF 系统能力: Kernel: 6.14.0, Sockmap: ✓, XDP: ✓, Per-CPU Map: ✓
[INFO] 加载 eBPF 程序...
[INFO] ✅ eBPF 程序加载成功
```
- ⚠️ **会尝试加载 eBPF 程序**
- ⚠️ **但当前的 Map 管理器只是占位实现**
- ❌ **无法真正使用 eBPF Map（因为使用的是普通 HashMap）**

## 为什么 `bpftool prog list` 看不到程序？

因为：

1. **在 kernel 4.4.0**: 检测到不支持，根本不尝试加载
2. **在 kernel 6.14.0**: 虽然会加载 eBPF 程序对象，但：
   - 当前的 SockmapManager 等只是**占位实现**
   - 使用的是普通 `HashMap`，不是 eBPF Map
   - 没有真正 attach 程序到 hook 点
   - 所以 eBPF 程序虽然加载但未激活

## 下一步开发 🚧

要真正让 eBPF 工作在内核中，需要：

### 关键任务 1: 重写 SockmapManager
```rust
pub struct SockmapManager {
    // 当前: 占位实现
    connections: Arc<Mutex<HashMap<RawFd, RawFd>>>,  ❌

    // 需要: 真正的 eBPF Map
    sock_map: SockHash<u64>,  ✅
    connection_map: HashMap<u64, u64>,  ✅

    // 需要: attach 程序
    program: SkMsg,  ✅
}

impl SockmapManager {
    pub fn new(bpf: &mut Bpf) -> Result<Self> {
        // 1. 获取 Map 引用
        let sock_map: SockHash<_, u64> = SockHash::try_from(bpf.map_mut("SOCK_MAP")?)?;

        // 2. 加载并 attach SK_MSG 程序
        let program: &mut SkMsg = bpf.program_mut("redirect_msg")?.try_into()?;
        program.load()?;
        program.attach(&sock_map)?;

        Ok(Self { sock_map, ... })
    }

    pub fn register_pair(&mut self, client_fd: RawFd, target_fd: RawFd) -> Result<()> {
        // 获取 socket cookie
        let client_cookie = self.get_socket_cookie(client_fd)?;
        let target_cookie = self.get_socket_cookie(target_fd)?;

        // 更新 eBPF Map
        self.connection_map.insert(client_cookie, target_cookie, 0)?;
        self.sock_map.insert(client_cookie, client_fd, 0)?;

        Ok(())
    }
}
```

### 关键任务 2: 重写 EbpfDnsCache
```rust
pub struct EbpfDnsCache {
    // 当前: 占位实现
    cache: Arc<RwLock<HashMap<String, DnsCacheEntry>>>,  ❌

    // 需要: 真正的 eBPF LRU Map
    dns_cache_map: LruHashMap<u64, DnsRecord>,  ✅
}

impl EbpfDnsCache {
    pub fn new(bpf: &mut Bpf, max_entries: usize) -> Result<Self> {
        let dns_cache_map: LruHashMap<_, u64, DnsRecord> =
            LruHashMap::try_from(bpf.map_mut("DNS_CACHE")?)?;

        Ok(Self { dns_cache_map })
    }

    pub fn lookup(&mut self, domain: &str) -> Option<IpAddr> {
        let key = self.domain_to_hash(domain);
        self.dns_cache_map.get(&key, 0).ok()
            .map(|record| record.ip_addr)
    }
}
```

### 关键任务 3: 修改 EbpfManager
```rust
impl EbpfManager {
    pub fn new(config: EbpfConfig) -> Result<Self> {
        // ...

        // 加载 eBPF 程序
        let mut bpf = Self::load_ebpf_program()?;

        // 传递 bpf 引用给各个组件
        let sockmap = if config.sockmap_enabled {
            Some(SockmapManager::new(&mut bpf)?)  // 传递 bpf
        } else {
            None
        };

        let dns_cache = if config.dns_cache_enabled {
            Some(EbpfDnsCache::new(&mut bpf, config.dns_cache_size)?)  // 传递 bpf
        } else {
            None
        };

        Ok(Self {
            _ebpf: Some(bpf),  // 保持 bpf 引用
            sockmap,
            dns_cache,
            ...
        })
    }
}
```

### 关键任务 4: XDP 程序 attach
```rust
impl XdpManager {
    pub fn new(bpf: &mut Bpf, interface: String) -> Result<Self> {
        // 获取 XDP 程序
        let program: &mut Xdp = bpf.program_mut("xdp_ip_filter")?.try_into()?;
        program.load()?;

        // Attach 到网络接口
        let link_id = program.attach(&interface, XdpFlags::default())?;

        Ok(Self {
            interface,
            link_id,
            ...
        })
    }
}
```

## 预期结果 🎯

完成上述任务后，在 kernel 6.14.0 环境中运行：

```bash
$ sudo ./target/release/sni-proxy config-ebpf.json

[INFO] 加载 eBPF 程序...
[INFO] ✓ 从嵌入字节码加载 eBPF 程序成功
[INFO] ✓ Sockmap 初始化成功，程序已 attach
[INFO] ✓ DNS 缓存初始化成功，Map 已创建
[INFO] ✓ XDP 程序已 attach 到 eth0
[INFO] eBPF 管理器初始化完成

$ sudo bpftool prog list | grep sni
42: sk_msg  name redirect_msg  tag abc123...
43: xdp     name xdp_ip_filter tag def456...

$ sudo bpftool map list | grep -E "SOCK_MAP|DNS_CACHE"
5: sockhash  name SOCK_MAP  flags 0x0
6: lru_hash  name DNS_CACHE  flags 0x0
```

## 技术难点 ⚡

1. **生命周期管理**: eBPF Map 和 Program 的生命周期必须绑定到 Bpf 对象
2. **错误处理**: 需要优雅处理加载失败、attach 失败等情况
3. **权限要求**: 需要 CAP_BPF 或 root 权限
4. **调试困难**: 内核日志、bpftool、perf 等工具需要配合使用

## 估算工作量 📊

- **重写 SockmapManager**: 4-6 小时
- **重写 EbpfDnsCache**: 2-3 小时
- **重写 EbpfStats**: 1-2 小时
- **重写 XdpManager**: 2-3 小时
- **集成测试和调试**: 4-6 小时
- **总计**: 约 13-20 小时

## 当前价值 ✨

虽然 eBPF 程序还未真正加载到内核，但当前实现已经提供了：

1. ✅ **完整的架构框架**: 各个组件接口已定义
2. ✅ **优雅降级机制**: kernel 不支持时自动回退
3. ✅ **配置文件支持**: 用户可控制 eBPF 功能
4. ✅ **主程序集成**: DNS 缓存查询等逻辑已集成
5. ✅ **编译基础设施**: eBPF 程序自动编译

## 结论 📝

**当前状态**: eBPF 框架已搭建，但 Map 操作是占位实现

**在 kernel 4.4.0**: 正确检测并降级，程序可以正常运行（传统模式）

**在 kernel 6.14.0**:
- 会尝试加载 eBPF 程序对象 ✅
- 但 Map 操作仍是普通 HashMap ❌
- 程序未 attach，`bpftool` 看不到 ❌

**要真正启用 eBPF 加速**: 需要完成上述"下一步开发"中的所有任务

---

**最后更新**: 2025-12-05
**作者**: Claude Code
