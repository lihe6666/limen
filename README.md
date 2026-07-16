# Limen

> *limen*(拉丁语:门槛、阈限)—— 站在网站门口,决定谁能跨过这道界限。

基于 TUI 的 Web 应用防火墙(WAF),**三级漏斗检测**:① 本地规则引擎(微秒,高精度)→ ② char n-gram 分类器(毫秒,高召回,补规则漏报)→ ③ 大模型(LLM)研判(秒级,灰色地带定夺)。反向代理模式,给网站前置一层安全防护,并在终端实时可视化流量与拦截。

## 特性

- **反向代理**:`用户 → Limen → 源站`,透明转发任意方法/路径。
- **一级规则引擎**(同步、零延迟、**13类攻击**):SQL 注入、XSS、路径穿越、命令注入、SSRF、RCE/Log4j/JNDI、SSTI 模板注入、XXE、NoSQL 注入、LDAP 注入、CRLF 注入、信息泄露/敏感文件探测、扫描器 UA;扫 path/query/body + 请求头;URL 迭代解码 + `\xNN`/`\uHHHH`/HTML 实体等混淆归一化;aho-corasick 重叠匹配 + 结构化正则。明确恶意直接拦截。
- **二级 n-gram 分类器**(本地、毫秒级、**可选**):char n-gram(2..4)+ crc32 hashing + 逻辑回归,加载 `ml/model.bin`(见 `ml/ngram_clf.py`,支持叠加再训练)。补规则引擎对混淆/新型 payload 的漏报;**不直接拦截**,只把规则判 Allow 但得分高的请求提升为"可疑"送 LLM 复核。由 `config.toml [detection] ngram_model` 开启,不配则跳过。
- **三级 LLM 研判**(异步 + 缓存,**配置驱动、接口可扩展**):规则或分类器判为"可疑"的灰色请求送 LLM 定夺。
  - 内置一个配置驱动的 OpenAI 兼容 provider,改 `base_url`/`model` 即可对接 OpenAI / Ollama / vLLM / DeepSeek / Groq 等所有 OpenAI 兼容端点。
  - 异形端点(非 OpenAI 兼容的请求/响应格式)由外部实现 `LlmProvider` trait 接入,编排层不变。
  - 统一结构化 JSON 裁决;TTL 缓存避免重复调用;超时/故障按 `fail_open`/`fail_close` 降级,绝不阻塞主链路。
- **TUI 仪表盘**(ratatui):实时流量表(彩色区分放行/可疑/拦截)、统计、模式、封禁数。
- **IP 黑名单**:同一 IP 多次拦截自动封禁,封禁 IP 请求直接短路。
- **拦截/监控双模式**:监控模式下检测照跑、事件照记,但一律放行(上线前调参用)。
- **CLI 管理命令**:`limen get health` 检查 WAF 状态,`limen get bypass / blacklist` 查看运行时数据,`limen set bypass add/remove` 动态管理直通白名单。
- **请求体大小限制**:可配置,超限返回 413 Payload Too Large。
- **上游超时控制**:可配置,超时返回 502 Bad Gateway。
- **缺口捕获 + 规则蒸馏**:运行时规则漏判自动记录(`gap_log`),`limen learn` 用 LLM 提议候选规则并通过白样本误报闸门校验,产出零误报候选供人工审核采纳。
- **离线评测**:`limen eval [--llm]` 用 BlazeHTTP 33k 样本量化检出率/误报率/准确率。

## 构建与运行

```sh
cargo build --release
./target/release/limen [配置文件路径]   # 默认读 ./config.toml,不存在则用内置默认
```

服务器/容器环境自动降级为 headless 模式(无 TUI),仅跑反向代理。也可显式 `config.toml` 中设 `headless = true`。

启动后进入 TUI。快捷键:

| 键 | 作用 |
|---|---|
| `q` / `Esc` / `Ctrl-C` | 退出 |
| `m` | 切换 拦截(ENFORCE)/ 监控(MONITOR)模式 |
| `u` | 清空 IP 黑名单 |

日志写入配置的 `log_file`(默认 `limen.log`),不污染界面。

## 配置(config.toml)

```toml
listen = "127.0.0.1:8080"          # WAF 监听地址
upstream = "http://127.0.0.1:8000" # 源站(转发目标)
log_file = "limen.log"
db_path = "limen.db"               # SQLite 数据库,空=纯内存模式(黑名单/直通/日志不持久)
headless = false                   # 无界面守护进程模式(服务器/Docker);无 TTY 自动降级
trusted_proxies = []               # 前置 nginx/caddy 的 IP;配了才会信任 X-Forwarded-For
real_ip_header = "X-Forwarded-For" # 取真实客户端 IP 的请求头

[detection]
block_threshold = 100              # 规则分数达此值直接拦截
suspicious_threshold = 40          # 达此值但未到 block → 送 LLM 研判
ngram_model = "ml/model.bin"       # 二级 n-gram 分类器;留空/删除则不启用第二层
ngram_threshold = 0.9              # 分类器得分达此值 → 提升为可疑送 LLM
upstream_timeout_secs = 30         # 上游(源站)请求超时秒数,0=不超时
max_body_bytes = 10485760          # 最大请求体字节,超限返回 413;0=沿用 10MB 默认
gap_log = "gaps.jsonl"             # 缺口捕获 JSONL;留空则不启用(规则漏判自动记录)
bypass_paths = []                  # 直通白名单,以 / 结尾=前缀匹配,否则精确匹配
disabled_categories = []           # 禁用的规则类别(如 ["Scanner","InfoDisclosure"])

[llm]
enabled = true
provider = "openai_compat"              # 内置唯一;其他值需外部实现 LlmProvider trait
model = "deepseek-chat"                 # 取决于端点: gpt-4o-mini / llama3.1 等
base_url = "https://api.deepseek.com"   # OpenAI 兼容端点;Ollama 填 http://localhost:11434/v1
api_key_env = "OPENAI_API_KEY"          # 从该环境变量读取密钥(绝不写死);本地 Ollama 可留空
timeout_ms = 15000                      # 单次研判超时(毫秒)
fail_mode = "fail_open"                 # 超时/故障时:fail_open 放行 | fail_close 拦截
```

对接不同端点只需改 `base_url` + `model`(鉴权走 `Authorization: ***`)。base_url 留空默认 `https://api.openai.com/v1`。
需要非 OpenAI 兼容的端点时,在外部实现 `LlmProvider` trait 并在 `from_config` 注册即可。

## 架构

```
用户 → [反向代理] → ① 规则引擎(13类攻击) ──明确恶意→ 403
                         │
                      正常/低分 → ② n-gram 分类器(可选)──得分高→ 提升为可疑
                         │                              └─低分→ 转发源站
                      可疑灰色 → ③ LLM 研判(配置驱动)──高危→ 403
                         │                            └─安全→ 转发
                         │
                   事件流(mpsc)→ [TUI 仪表盘]
```

模块:`proxy`(代理+流水线)、`engine/rules`(规则引擎)、`engine/ngram`(n-gram 分类器)、`engine/llm`(研判编排+provider)、`engine/verdict`(裁决类型)、`eval`(离线评测)、`learn`(规则蒸馏)、`state`(黑名单/模式)、`tui`(仪表盘)、`event`、`config`。

### 规则覆盖范围

| 类别 | 条数 | 说明 |
|---|---|---|
| SQLi | 22 | union select、报错/盲注函数、Oracle/MySQL 存储过程 |
| XSS | 20 | script、事件处理器、`<svg>/<iframe>`、HTML 实体编码 |
| PathTraversal | 9 | ../、/etc/passwd、php://filter、expect:// |
| CommandInjection | 16 | shell 元字符、PowerShell、Python 命令执行 |
| SSRF | 3 + 正则 | gopher://、dict://、内网 IP 正则 |
| RCE / JNDI / Log4j | 16 | `${jndi:ldap:}`、`Runtime.exec`、`os.system()` |
| SSTI | 11 | `{{config}}`、`{{7*7}}`、`__class__`、`freemarker` |
| XXE | 10 | `<!ENTITY`、`SYSTEM "file:` |
| NoSQLi | 6 | `$ne`、`$regex`、`$where` |
| LDAPi | 7 | `*)(uid=`、`*)(cn=` |
| CRLF | 8 | `%0d%0aSet-Cookie`、`%0d%0aLocation` |
| InfoDisclosure | 9 | `/.git/`、`/.env`、`id_rsa`、`.htpasswd` |
| Scanner UA | 23 | sqlmap、nuclei、burpsuite、zap、wfuzz、ffuf 等 |

## 部署在 nginx / caddy 后面

Limen 不终结 TLS,标准部署是前置 nginx 或 caddy 终结 HTTPS 后再反代到 Limen。**必须配置 `trusted_proxies` 指向前置代理的 IP**,否则 Limen 会把所有请求的客户端 IP 都算成前置代理那一个地址,IP 黑名单攒够封禁阈值后会自封代理,导致整站不可访问。

**Limen 端 `config.toml` 关键片段:**

```toml
headless = true                     # 无界面守护进程模式(服务器/Docker)
listen = "127.0.0.1:8080"           # 仅侦听本地回环,由前置代理转发
upstream = "http://192.168.1.100:8000"  # 真实源站地址
trusted_proxies = ["127.0.0.1"]     # 前置 nginx/caddy 的 IP;只有来自此列表的请求才会信任 X-Forwarded-For
real_ip_header = "X-Forwarded-For"  # 默认值,可不写;从该请求头取真实客户端 IP
```

**nginx 示例:**

```nginx
server {
    listen 443 ssl;
    server_name example.com;

    ssl_certificate     /etc/ssl/certs/example.com.pem;
    ssl_certificate_key /etc/ssl/private/example.com.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

**caddy 示例:**

```caddy
example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy 默认自动添加 `X-Forwarded-For` 和 `X-Forwarded-Proto`,无需手动设置转发头。

> **安全提示:**`trusted_proxies` 只填你自己前置代理的 IP(例如 `127.0.0.1` 或内网 IP),不要填入任何不可信来源。如果前置代理在公网且 IP 不固定,考虑用内网回环或私有网段进行转发。

### 健康检查

Limen 不提供 HTTP 健康检查端点（避免与后端业务路由冲突）。改用 CLI 命令：

```sh
# systemd service 的 ExecStartPre/ExecStop 或定时检查
limen get health

# Docker 容器健康检查
HEALTHCHECK --interval=30s --timeout=5s CMD limen get health || exit 1
```

## 测试与离线评测

```sh
cargo test                              # 单测:规则引擎、eval 解析、n-gram parity
cargo run --release -- eval             # BlazeHTTP 33k 样本量化规则引擎检出率/误报率
OPENAI_API_KEY=… cargo run --release -- eval --llm   # 三级漏斗端到端指标(含 LLM)
```

### 运行时管理

```sh
limen get health                        # 健康检查(数据库连通性、配置摘要)
limen get bypass                        # 查看直通白名单
limen get blacklist                     # 查看黑名单
limen set bypass add /internal/         # 运行时添加直通路径
limen set bypass remove /internal/      # 运行时移除直通路径
```

> `get` 和 `set` 子命令直接操作 SQLite 文件,不需要 WAF 处于运行状态。

### 规则蒸馏

```sh
limen learn [--whites <白样本目录>] [gaps.jsonl]
# 读缺口捕获 JSONL → LLM 提议候选规则 → 白样本误报闸门 → 输出零误报候选
```

`eval` 依赖 `benchmarks/blazehttp/` 样本集(GPL-3.0,不随仓库分发,见 CLAUDE.md)。n-gram 模型训练/叠加训练/导出见 `ml/ngram_clf.py`。
