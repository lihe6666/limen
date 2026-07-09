# Limen

> *limen*(拉丁语:门槛、阈限)—— 站在网站门口,决定谁能跨过这道界限。

基于 TUI 的 Web 应用防火墙(WAF),**三级漏斗检测**:① 本地规则引擎(微秒,高精度)→ ② char n-gram 分类器(毫秒,高召回,补规则漏报)→ ③ 大模型(LLM)研判(秒级,灰色地带定夺)。反向代理模式,给网站前置一层安全防护,并在终端实时可视化流量与拦截。

## 特性

- **反向代理**:`用户 → Limen → 源站`,透明转发任意方法/路径。
- **一级规则引擎**(同步、零延迟):SQL 注入、XSS、路径穿越、命令注入、Log4Shell/SSTI/SSRF、扫描器 UA;扫 path/query/body + 请求头;URL 迭代解码 + `\xNN`/`\uHHHH`/HTML 实体等混淆归一化;aho-corasick 重叠匹配 + 结构化正则。明确恶意直接拦截。
- **二级 n-gram 分类器**(本地、毫秒级、**可选**):char n-gram(2..4)+ crc32 hashing + 逻辑回归,加载 `ml/model.bin`(见 `ml/ngram_clf.py`,支持叠加再训练)。补规则引擎对混淆/新型 payload 的漏报;**不直接拦截**,只把规则判 Allow 但得分高的请求提升为"可疑"送 LLM 复核。由 `config.toml [detection] ngram_model` 开启,不配则跳过。
- **三级 LLM 研判**(异步 + 缓存,**配置驱动、接口可扩展**):规则或分类器判为"可疑"的灰色请求送 LLM 定夺。
  - 内置一个配置驱动的 OpenAI 兼容 provider,改 `base_url`/`model` 即可对接 OpenAI / Ollama / vLLM / DeepSeek / Groq 等所有 OpenAI 兼容端点。
  - 异形端点(非 OpenAI 兼容的请求/响应格式)由外部实现 `LlmProvider` trait 接入,编排层不变。
  - 统一结构化 JSON 裁决;TTL 缓存避免重复调用;超时/故障按 `fail_open`/`fail_close` 降级,绝不阻塞主链路。
- **TUI 仪表盘**(ratatui):实时流量表(彩色区分放行/可疑/拦截)、统计、模式、封禁数。
- **IP 黑名单**:同一 IP 多次拦截自动封禁,封禁 IP 请求直接短路。
- **拦截/监控双模式**:监控模式下检测照跑、事件照记,但一律放行(上线前调参用)。

## 构建与运行

```sh
cargo build --release
./target/release/limen [配置文件路径]   # 默认读 ./config.toml,不存在则用内置默认
```

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

[detection]
block_threshold = 100        # 规则分数达此值直接拦截
suspicious_threshold = 40    # 达此值但未到 block → 送 LLM 研判
ngram_model = "ml/model.bin" # 二级 n-gram 分类器模型;留空/删除则不启用第二层
ngram_threshold = 0.9        # 分类器得分达此值 → 把规则判 Allow 的请求提升为可疑送 LLM

[llm]
enabled = true
provider = "openai_compat"              # 内置唯一;其他值需外部实现 LlmProvider trait
model = "gpt-4o-mini"                   # 或 deepseek-chat / llama3.1 等,取决于端点
base_url = "http://localhost:11434/v1"  # OpenAI 兼容端点;Ollama 示例。留空默认 https://api.openai.com/v1
api_key_env = "OPENAI_API_KEY"          # 从该环境变量读取密钥(绝不写死);本地 Ollama 可留空
timeout_ms = 2000                       # 单次研判超时
fail_mode = "fail_open"                 # 超时/故障时:fail_open 放行 | fail_close 拦截
```

对接不同端点只需改 `base_url` + `model`(鉴权走 `Authorization: Bearer`,留空 `base_url` 默认 `https://api.openai.com/v1`)。
需要非 OpenAI 兼容的端点时,在外部实现 `LlmProvider` trait 并在 `from_config` 注册即可。

## 架构

```
用户 → [反向代理] → ① 规则引擎 ──明确恶意→ 403
                         │
                      正常/低分 → ② n-gram 分类器(可选)──得分高→ 提升为可疑
                         │                              └─低分→ 转发源站
                      可疑灰色 → ③ LLM 研判(配置驱动)──高危→ 403
                         │                            └─安全→ 转发
                         │
                   事件流(mpsc)→ [TUI 仪表盘]
```

模块:`proxy`(代理+流水线)、`engine/rules`(规则)、`engine/ngram`(n-gram 分类器)、`engine/llm`(研判编排+provider)、`engine/verdict`(裁决类型)、`eval`(离线评测)、`state`(黑名单/模式)、`tui`(仪表盘)、`event`、`config`。

## 测试与离线评测

```sh
cargo test                              # 单测:规则引擎、eval 解析、n-gram parity(与 Python 训练侧逐位一致)
cargo run --release -- eval             # 用 BlazeHTTP 样本量化规则/规则+ngram 的检出率/误报率
OPENAI_API_KEY=… cargo run --release -- eval --llm   # 三级漏斗端到端指标
```

`eval` 依赖 `testdata/blazehttp/` 样本集(GPL-3.0,不随仓库分发,见 CLAUDE.md)。n-gram 模型训练/叠加训练/导出见 `ml/ngram_clf.py`。
