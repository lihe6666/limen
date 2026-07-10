//! 配置加载:从 TOML 文件读取,缺省字段用 serde 默认值填充。
//! 未来阶段(LLM、规则开关)的字段现在就先定义好,避免后续改动配置结构。

use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    /// WAF 监听地址,如 "127.0.0.1:8080"
    #[serde(default = "default_listen")]
    pub listen: String,

    /// 源站地址(转发目标),如 "http://127.0.0.1:8000"
    #[serde(default = "default_upstream")]
    pub upstream: String,

    /// 日志文件路径(TUI 模式下不能打印到 stdout,故落文件)
    #[serde(default = "default_log_file")]
    pub log_file: String,

    /// 无界面守护进程模式:只跑反向代理、不起 TUI。
    /// 服务器/容器等无 TTY 环境必须开启;未显式配置时,检测到 stdout 非终端会自动降级为 headless。
    #[serde(default)]
    pub headless: bool,

    #[serde(default)]
    pub llm: LlmConfig,

    #[serde(default)]
    pub detection: DetectionConfig,
}

/// LLM 研判层配置。provider 无关:通过 `provider` + `base_url` 选择任意厂商/端点。
#[derive(Debug, Clone, Deserialize)]
pub struct LlmConfig {
    /// 是否启用二级 LLM 研判(关闭时只跑规则引擎)
    #[serde(default)]
    pub enabled: bool,

    /// provider 类型,仅内置 openai_compat(配置驱动,兼容 OpenAI/DeepSeek/Ollama/vLLM/Groq 等)
    #[serde(default = "default_provider")]
    pub provider: String,

    /// 模型名,如 "claude-haiku-4-5"、"gpt-4o-mini"、"llama3.1"
    #[serde(default = "default_model")]
    pub model: String,

    /// 自定义端点用;本地 Ollama 填 "http://localhost:11434/v1"
    #[serde(default)]
    pub base_url: String,

    /// 从哪个环境变量读取 API key(绝不在配置里硬编码密钥)
    #[serde(default = "default_api_key_env")]
    pub api_key_env: String,

    /// 单次研判超时(毫秒)
    #[serde(default = "default_llm_timeout_ms")]
    pub timeout_ms: u64,

    /// LLM 故障/超时时的行为:fail_open(放行) | fail_close(拦截)
    #[serde(default = "default_fail_mode")]
    pub fail_mode: String,
}

/// 一级规则引擎配置。
#[derive(Debug, Clone, Deserialize)]
pub struct DetectionConfig {
    /// 规则命中即拦截的最低分数阈值(达到/超过 → Block)
    #[serde(default = "default_block_threshold")]
    pub block_threshold: u32,

    /// 达到该分数但未到 block 阈值 → 视为可疑,送 LLM 研判
    #[serde(default = "default_suspicious_threshold")]
    pub suspicious_threshold: u32,

    /// ngram 模型文件路径,None 表示不启用第二层分类器
    #[serde(default)]
    pub ngram_model: Option<String>,

    /// ngram 分类器得分阈值:规则判 Allow 但 score >= 此值 → 提升为 Suspicious
    #[serde(default = "default_ngram_threshold")]
    pub ngram_threshold: f32,

    /// 禁用的规则类别,空 = 全启用
    #[serde(default)]
    pub disabled_categories: Vec<String>,

    /// 缺口捕获 JSONL 文件路径,None=不启用。规则漏判但被更高级别(ngram/LLM)抓获的请求会写入此文件
    #[serde(default)]
    pub gap_log: Option<String>,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            provider: default_provider(),
            model: default_model(),
            base_url: String::new(),
            api_key_env: default_api_key_env(),
            timeout_ms: default_llm_timeout_ms(),
            fail_mode: default_fail_mode(),
        }
    }
}

impl Default for DetectionConfig {
    fn default() -> Self {
        Self {
            block_threshold: default_block_threshold(),
            suspicious_threshold: default_suspicious_threshold(),
            ngram_model: None,
            ngram_threshold: default_ngram_threshold(),
            disabled_categories: Vec::new(),
            gap_log: None,
        }
    }
}

impl Config {
    /// 从 TOML 文件加载;文件不存在时返回全默认配置。
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let path = path.as_ref();
        if !path.exists() {
            tracing::warn!("配置文件 {} 不存在,使用默认配置", path.display());
            return Ok(Self::default());
        }
        let text = std::fs::read_to_string(path)?;
        let cfg: Config = toml::from_str(&text)?;
        Ok(cfg)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            upstream: default_upstream(),
            log_file: default_log_file(),
            headless: false,
            llm: LlmConfig::default(),
            detection: DetectionConfig::default(),
        }
    }
}

fn default_listen() -> String {
    "127.0.0.1:8080".to_string()
}
fn default_upstream() -> String {
    "http://127.0.0.1:8000".to_string()
}
fn default_log_file() -> String {
    "limen.log".to_string()
}
fn default_provider() -> String {
    "openai_compat".to_string()
}
fn default_model() -> String {
    "gpt-4o-mini".to_string()
}
fn default_api_key_env() -> String {
    "OPENAI_API_KEY".to_string()
}
fn default_llm_timeout_ms() -> u64 {
    2000
}
fn default_fail_mode() -> String {
    "fail_open".to_string()
}
fn default_block_threshold() -> u32 {
    100
}
fn default_suspicious_threshold() -> u32 {
    40
}
fn default_ngram_threshold() -> f32 {
    0.9
}
