# 多阶段构建 - 构建阶段
FROM rust:1.83-slim-bookworm AS builder

# 安装构建依赖
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 先复制依赖文件，利用 Docker 缓存
COPY Cargo.toml Cargo.lock ./

# 创建虚拟的 src 来预编译依赖
RUN mkdir src && \
    echo 'fn main() { println!("placeholder"); }' > src/main.rs && \
    cargo build --release && \
    rm -rf src target/release/deps/sni_proxy*

# 复制源代码并构建
COPY src ./src
COPY examples ./examples

RUN cargo build --release

# 运行阶段 - 使用最小基础镜像
FROM debian:bookworm-slim

# 安装运行时依赖
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && update-ca-certificates

# 创建非 root 用户
RUN groupadd -r sniproxy && useradd -r -g sniproxy sniproxy

WORKDIR /app

# 从构建阶段复制可执行文件
COPY --from=builder /app/target/release/sni-proxy /app/sni-proxy

# 复制配置文件
COPY config.example.json /app/config.example.json
COPY config.docker.json /app/config.json

# 创建日志目录并设置权限
RUN mkdir -p /app/logs && chown -R sniproxy:sniproxy /app

# 切换到非 root 用户
USER sniproxy

# 暴露端口 (SNI 代理端口)
EXPOSE 8443

# 设置环境变量
ENV RUST_LOG=info

# 健康检查
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD test -f /proc/1/status || exit 1

# 启动命令 - 如果存在 config.json 则使用它，否则使用示例配置
CMD ["/app/sni-proxy", "config.json"]
