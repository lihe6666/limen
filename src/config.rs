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

    /// SQLite 数据库文件路径,空=不启用持久化(纯内存模式)
    #[serde(default)]
    pub db_path: String,

    /// 无界面守护进程模式:只跑反向代理、不起 TUI。
    /// 服务器/容器等无 TTY 环境必须开启;未显式配置时,检测到 stdout 非终端会自动降级为 headless。
    #[serde(default)]
    pub headless: bool,

    #[serde(default)]
    pub llm: LlmConfig,

    /// 可信前置代理 IP 列表(精确 IP 字符串,如 ["127.0.0.1", "::1"])
    /// 空 = 不信任任何转发头,回退用对端 IP
    #[serde(default)]
    pub trusted_proxies: Vec<String>,

    /// 取真实 IP 的头名,默认 "X-Forwarded-For"
    #[serde(default = "default_real_ip_header")]
    pub real_ip_header: String,

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

    /// 直通白名单:命中则跳过三级检测。以 / 结尾=前缀匹配,否则精确匹配
    #[serde(default)]
    pub bypass_paths: Vec<String>,

    /// 上游(源站)请求超时秒数,0=不超时
    #[serde(default = "default_upstream_timeout")]
    pub upstream_timeout_secs: u64,

    /// 允许的最大请求体字节,超限返回 413。0=沿用硬编码默认(10MB)
    #[serde(default)]
    pub max_body_bytes: usize,

    /// per-IP 每秒请求数上限,0=不限流
    #[serde(default)]
    pub rate_limit_rps: u32,

    /// per-IP 突发容量,0=默认取 rps*2
    #[serde(default)]
    pub rate_limit_burst: u32,
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
            bypass_paths: Vec::new(),
            upstream_timeout_secs: default_upstream_timeout(),
            max_body_bytes: 0,
            rate_limit_rps: 0,
            rate_limit_burst: 0,
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
            db_path: String::new(),
            headless: false,
            trusted_proxies: Vec::new(),
            real_ip_header: default_real_ip_header(),
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

fn default_upstream_timeout() -> u64 {
    30
}

fn default_real_ip_header() -> String {
    "X-Forwarded-For".to_string()
}
