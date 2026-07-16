# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

Limen 是一个 Rust 编写的 TUI Web 应用防火墙（WAF）：反向代理模式，两层检测——本地规则引擎（同步、零延迟）+ 可插拔 LLM 二级研判（异步、带缓存/超时/降级）。代码注释与文档均为中文，新代码请保持一致。

## 常用命令

```sh
cargo test                              # 全部单测(规则引擎 + 评测解析)
cargo test sqli_union_select_blocks    # 跑单个测试(按名字过滤)
cargo build --release
./target/release/limen [config.toml]   # 启动 WAF + TUI;argv[1] 是配置路径,缺省 ./config.toml
cargo run --release -- eval [样本目录]  # 离线评测规则引擎,默认 benchmarks/blazehttp
```

注意 argv[1] 的双重语义：`eval` 触发评测子命令，其他值当作配置文件路径（见 `src/main.rs` 开头的分支）。

TUI 独占终端，运行时日志一律走 `tracing` 落文件（默认 `limen.log`）——**不要在运行时代码里 println**，会污染界面。`eval` 子命令是例外，它不启动 TUI，报告直接打 stdout。

## 架构

请求流水线在 `src/proxy.rs::pipeline()`，是理解全局的入口：

```
请求 → IP 黑名单短路 → RuleEngine::inspect(一级) → to_verdict(阈值映射)
        ├─ Block      → 403(enforce)或 放行+标注(monitor 模式)
        ├─ Suspicious ─┐
        └─ Allow ──→ NgramClassifier(二级,可选) score≥阈值则提升为 Suspicious
                       └─ Suspicious → LlmAdjudicator::adjudicate(三级,完全旁路 advisory:先放行转发,后台异步研判,只影响后续同类请求) → 命中缓存则拦截
                       └─ Allow      → 转发源站
所有结果 → mpsc 事件流 → TUI 仪表盘(src/tui/)
```
三级漏斗:① 规则(微秒,高精度) → ② char n-gram 分类器(毫秒,高召回,补规则漏报) → ③ LLM(秒级,灰色研判)。

- **分数契约**：`engine/rules.rs` 中每条规则带分数并累加，`engine/verdict.rs::to_verdict` 按阈值映射为裁决。默认 `block_threshold=100`（单条高置信规则即拦截）、`suspicious_threshold=40`（送 LLM）。阈值来自 `config.toml [detection]`。
- **检测面（已知缺口）**：引擎只扫 path + query + body（截断 16KB，`proxy.rs::MAX_INSPECT_BODY`）+ User-Agent。**不扫其他请求头**（Referer/Cookie 里的 payload 会漏），这是评测暴露的主要漏报来源之一。
- **LLM 层**（`engine/llm/`）：`mod.rs` 是编排（moka TTL 缓存 + tokio 超时 + fail_open/fail_close 降级），`provider.rs` 定义 `LlmProvider` trait（外部扩展点）。内置只有 `openai_compat.rs` 一个配置驱动的 OpenAI 兼容 provider——改 `base_url`/`model` 即可对接 OpenAI/DeepSeek/Ollama/vLLM/Groq。异形端点由外部实现 trait 并在 `from_config` 注册。注意结构化输出用 `json_object` 而非 `json_schema`（后者是 OpenAI 专属，DeepSeek 等会拒绝）；`provider.rs::parse_verdict` 是各端点的统一兜底解析层。
- **二级 n-gram 分类器**（`engine/ngram.rs`）：可选。char n-gram（n=2..4）+ crc32 hashing + 逻辑回归，加载 `ml/model.bin`（Python `ml/ngram_clf.py` 训练+`export` 导出，支持 `update` 叠加训练）。**它只把规则判 Allow 的请求提升为 Suspicious 送 LLM，不直接拦截**。由 `config.toml [detection] ngram_model`/`ngram_threshold` 开启。⚠️ Python↔Rust 特征提取必须逐位一致（否则权重失效）——`ngram.rs` 的 parity 测试读 `ml/parity.json` 断言，改任一侧特征逻辑都要重新 `export` 并跑 parity。
- **双模式**：monitor 模式（TUI 按 `m` 切换）下检测照跑、事件照记但一律放行，用于上线前调参。

## 规则评测（改规则必跑）

`benchmarks/blazehttp/` 是 BlazeHTTP 测试集（658 黑样本 + 33,219 白样本，原始 HTTP 请求格式），**已 gitignore、GPL-3.0 许可，不得提交进仓库**；缺失时从 https://github.com/chaitin/blazehttp 获取 testcases。

`cargo run --release -- eval` 输出检出率/误报率/F1（严格与宽松两个口径）、白样本误报驱动规则 Top 15、漏报/误报明细（`target/eval/*.txt`）。改动 `rules.rs` 或阈值后跑一次，与基线对照（2026-07 基线：严格口径检出率 17.5%、误报率 0.09%）。评测的样本解析在 `src/eval.rs`，body 截断刻意与 proxy 对齐以代表线上行为。

# Claude Code 指挥官协议

你当前的角色是【系统架构师/规划总指挥】。你的任务是统筹全局，严禁亲自编写大段的具体业务代码。你必须调度 DeepSeek Agent 团队来完成代码实现。

## 你可以调动的外部 Agent 工具：
你可以随时在 Bash 终端中运行以下命令来唤醒 DeepSeek 执行者：
`opencode run --model deepseek/deepseek-v4-flash "轻量的"` #
`opencode run -model deepseek/deepseek-v4-pro "你的具体重构或编写指令"`

## 你的工作流（Workflow）：
1. **分析与拆解：** 收到用户需求后，先使用 `/plan` 模式拆解任务，列出需要修改的文件清单。
2. **多线程派发：** 针对不同的模块，分别组合不同的 Bash 命令，启动对应的 DeepSeek 实例。
   - 例如：`opencode run --model deepseek/deepseek-v4-flash "请帮我实现用户注册的输入校验逻辑"`
3. **成果审查：** DeepSeek 执行完毕后，利用你的文件读取工具检查代码，若有错误，继续调用 DeepSeek 修正。
