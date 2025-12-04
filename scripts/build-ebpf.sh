#!/bin/bash
# eBPF 程序构建脚本
#
# 此脚本用于编译 eBPF 内核态程序
#
# 使用方法:
#   ./scripts/build-ebpf.sh
#
# 要求:
#   - Rust 1.70+
#   - bpf-linker (cargo install bpf-linker)
#   - Linux 内核 4.14+

set -e

# 颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}===== eBPF 程序构建脚本 =====${NC}"

# 检查是否在项目根目录
if [ ! -f "Cargo.toml" ]; then
    echo -e "${RED}错误: 请在项目根目录运行此脚本${NC}"
    exit 1
fi

# 检查 Rust 版本
echo -e "${YELLOW}检查 Rust 版本...${NC}"
rust_version=$(rustc --version | awk '{print $2}')
echo "Rust 版本: $rust_version"

# 检查 bpf-linker
echo -e "${YELLOW}检查 bpf-linker...${NC}"
if ! command -v bpf-linker &> /dev/null; then
    echo -e "${RED}bpf-linker 未安装${NC}"
    echo "请运行: cargo install bpf-linker"
    exit 1
fi
echo "bpf-linker: $(bpf-linker --version)"

# 检查内核版本
echo -e "${YELLOW}检查内核版本...${NC}"
kernel_version=$(uname -r)
echo "内核版本: $kernel_version"

# 提取主版本和次版本
major=$(echo $kernel_version | cut -d. -f1)
minor=$(echo $kernel_version | cut -d. -f2)

if [ "$major" -lt 4 ] || ([ "$major" -eq 4 ] && [ "$minor" -lt 14 ]); then
    echo -e "${YELLOW}警告: 内核版本过低 (需要 >= 4.14)${NC}"
    echo "eBPF Sockmap 功能可能不可用"
fi

# 创建输出目录
mkdir -p target/bpf/programs
mkdir -p .cargo

# 配置 Cargo
echo -e "${YELLOW}配置 Cargo...${NC}"
cat > .cargo/config.toml << 'EOF'
[build]
target-dir = "target"

[unstable]
build-std = ["core"]

[target.bpfel-unknown-none]
linker = "bpf-linker"
rustflags = [
    "-C", "link-arg=--disable-memory-builtins",
    "-C", "linker-plugin-lto",
]

[target.bpfeb-unknown-none]
linker = "bpf-linker"
rustflags = [
    "-C", "link-arg=--disable-memory-builtins",
    "-C", "linker-plugin-lto",
]
EOF

echo "配置文件已创建: .cargo/config.toml"

# 确定目标架构
if [ "$(uname -m)" = "x86_64" ]; then
    target="bpfel-unknown-none"
elif [ "$(uname -m)" = "aarch64" ]; then
    target="bpfel-unknown-none"
else
    echo -e "${YELLOW}警告: 未识别的架构 $(uname -m)${NC}"
    target="bpfel-unknown-none"
fi

echo -e "${YELLOW}目标架构: $target${NC}"

# 编译 eBPF 程序
echo -e "${GREEN}编译 eBPF 程序...${NC}"
cd ebpf

if cargo build --release --target=$target; then
    echo -e "${GREEN}✓ eBPF 程序编译成功${NC}"
else
    echo -e "${RED}✗ eBPF 程序编译失败${NC}"
    exit 1
fi

cd ..

# 复制编译产物
echo -e "${YELLOW}复制编译产物...${NC}"
if [ -f "target/$target/release/sni-proxy" ]; then
    cp "target/$target/release/sni-proxy" target/bpf/programs/
    echo -e "${GREEN}✓ 编译产物已复制到 target/bpf/programs/${NC}"
else
    echo -e "${RED}✗ 找不到编译产物${NC}"
    exit 1
fi

# 检查编译产物
echo -e "${YELLOW}检查编译产物...${NC}"
file_info=$(file target/bpf/programs/sni-proxy)
echo "文件类型: $file_info"

if echo "$file_info" | grep -q "ELF"; then
    echo -e "${GREEN}✓ 编译产物是有效的 ELF 文件${NC}"
else
    echo -e "${RED}✗ 编译产物不是有效的 ELF 文件${NC}"
    exit 1
fi

# 显示文件大小
file_size=$(stat -f%z target/bpf/programs/sni-proxy 2>/dev/null || stat -c%s target/bpf/programs/sni-proxy)
echo "文件大小: $((file_size / 1024)) KB"

# 完成
echo -e "${GREEN}===== 构建完成 =====${NC}"
echo ""
echo "eBPF 程序位置: target/bpf/programs/sni-proxy"
echo ""
echo "下一步:"
echo "  1. 编译用户态程序: cargo build --release"
echo "  2. 运行程序 (需要 root): sudo ./target/release/sni-proxy"
echo ""
echo "注意:"
echo "  - 需要 Linux 内核 >= 4.14"
echo "  - 需要 root 权限或 CAP_BPF"
echo "  - 首次运行可能需要加载 eBPF 程序"
