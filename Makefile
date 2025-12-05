# SNI-Proxy Makefile
#
# 提供便捷的构建命令

.PHONY: help build build-ebpf build-release test clean install check fmt clippy

# 默认目标
help:
	@echo "SNI-Proxy 构建系统"
	@echo ""
	@echo "可用命令:"
	@echo "  make build         - 构建项目（debug 模式）"
	@echo "  make build-release - 构建项目（release 模式）"
	@echo "  make build-ebpf    - 构建 eBPF 程序"
	@echo "  make build-all     - 构建 eBPF + 用户态程序"
	@echo "  make test          - 运行测试"
	@echo "  make check         - 检查代码"
	@echo "  make fmt           - 格式化代码"
	@echo "  make clippy        - 运行 clippy"
	@echo "  make clean         - 清理构建产物"
	@echo "  make install       - 安装到系统"
	@echo ""
	@echo "eBPF 相关:"
	@echo "  make ebpf-check    - 检查 eBPF 支持"
	@echo "  make ebpf-info     - 显示 eBPF 信息"
	@echo ""

# 构建项目（debug 模式）
build:
	@echo "构建项目 (debug)..."
	cargo build

# 构建项目（release 模式）
build-release:
	@echo "构建项目 (release)..."
	cargo build --release
	@echo ""
	@echo "✓ 构建完成: target/release/sni-proxy"

# 构建 eBPF 程序
build-ebpf:
	@echo "构建 eBPF 程序..."
	@if [ ! -x "scripts/build-ebpf.sh" ]; then \
		chmod +x scripts/build-ebpf.sh; \
	fi
	@./scripts/build-ebpf.sh

# 构建所有（eBPF + 用户态）
build-all: build-ebpf build-release
	@echo ""
	@echo "✓ 所有构建完成"

# 运行测试
test:
	@echo "运行测试..."
	cargo test

# 运行测试（包括忽略的测试）
test-all:
	@echo "运行所有测试..."
	cargo test -- --include-ignored

# 检查代码
check:
	@echo "检查代码..."
	cargo check

# 格式化代码
fmt:
	@echo "格式化代码..."
	cargo fmt
	@cd ebpf && cargo fmt

# 运行 clippy
clippy:
	@echo "运行 clippy..."
	cargo clippy -- -D warnings

# 清理构建产物
clean:
	@echo "清理构建产物..."
	cargo clean
	@cd ebpf && cargo clean
	@rm -rf target/bpf
	@rm -rf .cargo/config.toml
	@echo "✓ 清理完成"

# 安装到系统
install: build-release
	@echo "安装到系统..."
	@sudo cp target/release/sni-proxy /usr/local/bin/
	@sudo chmod +x /usr/local/bin/sni-proxy
	@echo "✓ 安装完成: /usr/local/bin/sni-proxy"

# 卸载
uninstall:
	@echo "卸载..."
	@sudo rm -f /usr/local/bin/sni-proxy
	@echo "✓ 卸载完成"

# 检查 eBPF 支持
ebpf-check:
	@echo "检查 eBPF 支持..."
	@echo ""
	@echo "内核版本:"
	@uname -r
	@echo ""
	@echo "eBPF 文件系统:"
	@if [ -d "/sys/fs/bpf" ]; then \
		echo "✓ /sys/fs/bpf 存在"; \
	else \
		echo "✗ /sys/fs/bpf 不存在"; \
	fi
	@echo ""
	@echo "bpf-linker:"
	@if command -v bpf-linker >/dev/null 2>&1; then \
		echo "✓ $(shell bpf-linker --version)"; \
	else \
		echo "✗ 未安装 (运行: cargo install bpf-linker)"; \
	fi
	@echo ""
	@echo "推荐内核版本: >= 4.14 (Sockmap)"
	@echo "              >= 4.8  (XDP)"
	@echo "              >= 5.10 (最佳支持)"

# 显示 eBPF 信息
ebpf-info:
	@echo "eBPF 程序信息"
	@echo ""
	@if [ -f "target/bpf/programs/sni-proxy" ]; then \
		echo "位置: target/bpf/programs/sni-proxy"; \
		echo "大小: $$(du -h target/bpf/programs/sni-proxy | cut -f1)"; \
		echo "类型: $$(file target/bpf/programs/sni-proxy)"; \
	else \
		echo "✗ eBPF 程序未构建"; \
		echo "运行: make build-ebpf"; \
	fi

# 运行示例
run-example:
	@echo "运行 eBPF 示例..."
	cargo run --example ebpf_demo

# 运行项目
run: build
	@echo "运行项目..."
	cargo run

# 运行项目（release 模式）
run-release: build-release
	@echo "运行项目 (release)..."
	./target/release/sni-proxy

# 生成文档
doc:
	@echo "生成文档..."
	cargo doc --no-deps --open

# 开发模式：监听文件变化并自动重新编译
watch:
	@echo "开发模式（需要 cargo-watch）..."
	@if command -v cargo-watch >/dev/null 2>&1; then \
		cargo watch -x check -x test; \
	else \
		echo "✗ 未安装 cargo-watch"; \
		echo "安装: cargo install cargo-watch"; \
	fi

# 性能分析
bench:
	@echo "运行性能测试..."
	cargo bench

# 代码覆盖率（需要 tarpaulin）
coverage:
	@echo "生成代码覆盖率报告..."
	@if command -v cargo-tarpaulin >/dev/null 2>&1; then \
		cargo tarpaulin --out Html; \
	else \
		echo "✗ 未安装 cargo-tarpaulin"; \
		echo "安装: cargo install cargo-tarpaulin"; \
	fi
