# Limen WAF Docker 镜像（多阶段构建）
#
# 替代方案（全静态 musl，体积更小但 rusqlite bundled 编译需额外踩坑）:
#   改用 rust:alpine + musl-dev + sqlite-dev, 构建时加 RUSTFLAGS='-C target-feature=-crt-static'
#   运行阶段用 alpine:latest

# ── builder 阶段:编译 ──────────────────────────────────────────────
FROM rust:1-bookworm AS builder
WORKDIR /build

# 先复制 Cargo.toml/Cargo.lock 利用 Docker 缓存层加速依赖编译
COPY Cargo.toml Cargo.lock ./
# 创建最小 src 让 cargo 能解析依赖
RUN mkdir src && echo 'fn main() {}' > src/main.rs
RUN cargo build --release 2>/dev/null || true

# 复制完整源码并构建
COPY src/ ./src/
# touch 保证 src 时间戳晚于预编译,触发重新增量编译
RUN touch src/main.rs && cargo build --release

# ── runtime 阶段:运行 ──────────────────────────────────────────────
FROM debian:bookworm-slim

# ca-certificates 用于 reqwest TLS 校验
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 从 builder 复制二进制
COPY --from=builder /build/target/release/limen /usr/local/bin/limen

# 创建非 root 用户运行 WAF
RUN useradd --system --no-create-home --shell /usr/sbin/nologin limen

# 工作目录:config.toml、limen.db、日志均由此处产生/读取
WORKDIR /etc/limen
RUN chown limen:limen /etc/limen

USER limen
EXPOSE 8080
ENV RUST_LOG=info

ENTRYPOINT ["limen", "/etc/limen/config.toml"]
