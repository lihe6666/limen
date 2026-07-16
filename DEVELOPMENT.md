# Limen 开发文档

## 项目概览

Limen（拉丁语"门槛"）是一个 LLM 增强型 Web 应用防火墙（WAF），用 Rust 编写。

核心架构：**三级漏斗检测**

```
请求 → ① 规则引擎(13类攻击,微秒) ──明确恶意→ 403
              │
           正常/低分 → ② n-gram(可选,毫秒) ──高分→ 提升为可疑
              │                               └─低分→ 转发
           可疑灰色 → ③ LLM(秒级,配置驱动) ──高危→ 403
              │                           └─安全→ 转发
              │
         事件流(mpsc)→ [TUI 仪表盘 / headless drain]
```

## 目录结构

```
src/
├── main.rs          # 入口:CLI 解析 + WAF 启动 + 管理子命令
├── config.rs        # TOML 配置结构
├── proxy.rs         # axum 反向代理 + 检测流水线
├── state.rs         # 运行时控制(拦截/监控模式,自动封禁计数器)
├── storage.rs       # SQLite 持久化(黑名单/直通/审计日志)
├── event.rs         # WafEvent 类型定义
├── eval.rs          # limen eval:BlazeHTTP 离线评测
├── learn.rs         # limen learn:规则蒸馏
├── engine/
│   ├── mod.rs
│   ├── rules.rs     # 规则引擎(13类 140+ 条规则)
│   ├── verdict.rs   # Detection/Hit/Verdict 类型
│   ├── ngram.rs     # char n-gram 分类器(ML)
│   └── llm/
│       ├── mod.rs       # LlmAdjudicator:缓存+超时+降级编排
│       ├── provider.rs  # LlmProvider trait + 系统提示
│       └── openai_compat.rs  # OpenAI 兼容 provider 实现
└── tui/
    └── mod.rs       # ratatui 仪表盘
```

## 设计决策

### 为什么不走 HTTP 健康检查？

Limen 作为反向代理，HTTP `/health` 路径会和后端业务路由冲突。改用 CLI 子命令 `limen get health`，systemd/Docker 直接执行即可，不影响业务流量。

### SQLite 而非内存？

- IP 黑名单需要持久化，重启不丢失
- `bypass_paths` 运行时动态管理
- 热路径（每次请求的 `is_banned` / `is_bypass`）走内存缓存，O(1) 查询
- WAL 模式：读不阻塞写
- `db_path = ""` = 纯内存模式，零依赖

### Provider 可插拔

`LlmProvider` trait 在 `provider.rs` 定义，内置仅 `openai_compat`。切换厂商只改配置，新增异形端点只需外部实现 trait 并在 `from_config` 注册。

## 模块详解

### 规则引擎 (`engine/rules.rs`)

- LITERAL_RULES: 静态切片，每条 (模式, 类别, 分数)，aho-corasick 重叠匹配
- REGEX_DEFS: 需要上下文的正则规则
- SCANNER_UA: 扫描器 User-Agent 子串匹配
- `percent_decode_lossy` + `decode_escapes` 两次归一化覆盖 URL 编码和 `\x`/`\u`/HTML 实体混淆

**13 个攻击类别：**

| 类别 | 条数 | 关键特征 |
|---|---|---|
| SQLi | 22 | union select, sleep(), extractvalue(), dbms_pipe |
| XSS | 20 | `<script`, `onerror=`, `%3cscript`, `fromCharCode` |
| PathTraversal | 9 | `../`, `php://filter`, `expect://` |
| CommandInjection | 16 | `;cat`, `|bash`, `powershell -`, `Invoke-Expression` |
| SSRF | 3+正则 | `gopher://`, `dict://`, 内网 IP 正则 |
| RCE/JNDI | 16 | `${jndi:ldap:}`, `Runtime.getRuntime`, `os.system(` |
| SSTI | 11 | `{{config}}`, `{{7*7}}`, `__class__`, `freemarker` |
| XXE | 10 | `<!ENTITY`, `SYSTEM "file:` |
| NoSQLi | 6 | `$ne`, `$regex`, `$where` |
| LDAPi | 7 | `*)(uid=`, `*)(cn=` |
| CRLF | 8 | `%0d%0aSet-Cookie` |
| InfoDisclosure | 9 | `/.git/`, `/.env`, `id_rsa`, `.htpasswd` |
| Scanner UA | 23 | sqlmap, nuclei, burpsuite, wfuzz, ffuf |

### 存储层 (`storage.rs`)

SQLite WAL 模式，三张表：

```sql
bypass_paths(id, pattern UNIQUE, created_at, comment)
blacklist(id, ip UNIQUE, reason, blocked_at)
audit_log(id, time, client_ip, method, path, action, score, threat, status, detail, tier)
```

热路径查内存缓存（HashSet），变更写透（write-through）。

### 检测流水线 (`proxy.rs`)

1. **黑名单短路** → 封禁 IP 直接 403
2. **直通白名单** → 命中跳过三级检测直接转发
3. **一级规则引擎** → 明确恶意 Block，可疑 Suspicous，正常 Allow
4. **ngram 提升**（可选）→ 规则判 Allow 但 ngram 高分 → 提升为 Suspicious
5. **二级 LLM**（可选）→ 可疑请求异步研判 + TTL 缓存 + 超时降级
6. **监控模式** → 检测照跑但不拦截，上线前调参用

## 当前状态与剩余工作

### ✅ 已完成

| 模块 | 状态 |
|---|---|
| 反向代理 (axum) | ✅ 生产可用 |
| 规则引擎 (13类 140+规则) | ✅ 生产可用 |
| LLM 二级研判 (缓存+并发+降级) | ✅ 生产可用 |
| ngram ML 分类器 | ✅ 生产可用 |
| TUI 仪表盘 | ✅ 生产可用 |
| IP 自动封禁 + SQLite 持久化 | ✅ 生产可用 |
| 拦截/监控模式 | ✅ 生产可用 |
| 离线评测 (BlazeHTTP) | ✅ `limen eval` |
| 规则蒸馏 | ✅ `limen learn` |
| headless 模式 | ✅ 容器友好 |
| 可信代理 IP (X-Forwarded-For) | ✅ |
| 直通白名单 (SQLite+CLI) | ✅ |
| 上游超时控制 | ✅ `upstream_timeout_secs` |
| 请求体大小限制 | ✅ `max_body_bytes` → 413 |
| CLI 管理命令 | ✅ `get/set` 子命令 |
| 健康检查 | ✅ `limen get health` |
| --help 文档 | ✅ 含全部子命令 |
| README | ✅ 完整 |

### 🔜 待完成（P1 — 上线前建议）

| # | 任务 | 说明 | 预估 |
|---|---|---|---|
| 1 | **Docker 镜像** | 多阶段构建: `cargo build --release` → debian:bookworm-slim | ✅ 已完成 |
| 2 | **Graceful shutdown** | signal 等待 inflight 请求完成 | 1h |
| 3 | **日志轮转** | `rolling::daily` 按天切分 | ✅ 已完成 |
| 4 | **Systemd service** | `[Unit]` + `[Service]` + `ExecStart` 模板 | ✅ 已完成 |

### 🔮 远期规划（P2 — 上线后迭代）

| # | 任务 | 说明 |
|---|---|---|
| 5 | **Prometheus 指标** | 请求量、拦截率、延迟直方图、规则命中分布 |
| 6 | **请求速率限制** | per-IP 令牌桶，防 CC 攻击 |
| 7 | **热加载规则/配置** | SIGHUP 重读 rules.rs / config.toml，无需重启 |
| 8 | **CI (GitHub Actions)** | 自动 build + test + BlazeHTTP 评测 + 镜像构建 |
| 9 | **audit_log 写入** | `storage.append_audit_log` 已实现但未接入流水线 |
| 10 | **WebSocket 检测** | 目前只检测 HTTP，WS 无防护 |
| 11 | **性能基准** | 用 `limen eval` 跟踪每次规则变更的吞吐影响 |

## 构建与测试

```sh
# 开发构建
cargo build

# 生产构建
cargo build --release

# 运行（TUI 模式）
./target/release/limen

# 运行（headless 模式，服务器/容器）
headless=true ./target/release/limen

# 运行测试
cargo test

# 离线评测（需 benchmarks/blazehttp）
cargo run --release -- eval
cargo run --release -- eval --llm   # 含 LLM

# 规则蒸馏
limen learn gaps.jsonl
```

## CLI 参考

```
limen                        启动 WAF
limen <config>               指定配置文件
limen eval [--llm] [目录]    离线评测
limen learn [--whites] [<gaps.jsonl>]   规则蒸馏
limen get health             健康检查
limen get bypass             查看直通白名单
limen get blacklist          查看黑名单
limen set bypass add <路径>  添加直通路径
limen set bypass remove <路径>  移除直通路径
limen --help                 帮助
```

## 配置参考

关键配置项见 `config.toml`，核心参数：

| 参数 | 默认值 | 说明 |
|---|---|---|
| `listen` | `127.0.0.1:8080` | WAF 监听地址 |
| `upstream` | `http://127.0.0.1:8000` | 源站地址 |
| `db_path` | `limen.db` | SQLite 数据库；空=纯内存 |
| `headless` | `false` | 无界面模式 |
| `block_threshold` | `100` | 规则拦截阈值 |
| `suspicious_threshold` | `40` | 规则可疑阈值 |
| `upstream_timeout_secs` | `30` | 上游超时 |
| `max_body_bytes` | `10485760` | 最大请求体 |
| `bypass_paths` | `[]` | 直通白名单 |
| `disabled_categories` | `[]` | 禁用规则类别 |

## 部署拓扑

```
用户 ──HTTPS──→ nginx/caddy ──HTTP──→ Limen(:8080) ──HTTP──→ 源站(:8000)
                      │                      │
                  TLS 终止               headless 模式
                  trusted_proxies         健康检查: limen get health
                  X-Forwarded-For         SQLite: limen.db
```

> `trusted_proxies` 必须配置！否则 IP 黑名单会把前置代理自封。

## 容器 / systemd 部署

### Docker

```sh
# 构建镜像
docker build -t limen .

# 运行（挂载配置目录）
docker run -d \
  --name limen \
  -p 8080:8080 \
  -v /etc/limen:/etc/limen \
  limen

# 如需自定义 config.toml 或 ml/model.bin,放入宿主机 /etc/limen 目录再启动
```

镜像基于 `debian:bookworm-slim`（glibc），非静态链接。如需更小体积的全静态 musl 镜像，可将 builder/runtime 改为 `rust:alpine` + `alpine:latest` 并安装 `musl-dev sqlite-dev`，构建时设 `RUSTFLAGS='-C target-feature=-crt-static'`。

### systemd

```sh
# 安装
sudo cp deploy/limen.service /etc/systemd/system/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin limen
sudo mkdir -p /etc/limen
sudo cp config.toml /etc/limen/
# 如有 ngram 模型
sudo cp ml/model.bin /etc/limen/
sudo chown -R limen:limen /etc/limen

# 启动
sudo systemctl daemon-reload
sudo systemctl enable --now limen

# 查看状态/日志
sudo systemctl status limen
sudo journalctl -u limen -f
```

服务以 headless 模式运行（无 TTY 自动 fallback），配置中 `headless = true` 可显式声明。日志同时输出到 journald 和 `/etc/limen/` 下的按天轮转文件。安全加固项（NoNewPrivileges、ProtectSystem 等）已预设在 `deploy/limen.service` 中。
