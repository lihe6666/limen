//! LLM provider 抽象:统一 trait 与公共裁决类型,让编排层与具体厂商解耦。
//! 内置仅提供配置驱动的 OpenAI 兼容 provider,外部可通过实现 `LlmProvider` 接入任意端点。

use serde::Deserialize;

use crate::engine::verdict::RequestSummary;

/// 各 provider 统一返回的裁决(从模型 JSON 输出解析而来)。
#[derive(Debug, Clone, Deserialize)]
pub struct LlmVerdict {
    /// "allow" | "block"
    pub verdict: String,
    #[serde(default)]
    pub threat_type: String,
    #[serde(default)]
    pub confidence: f32,
    #[serde(default)]
    pub reason: String,
    /// 2-3 句更详细的判断依据:命中了什么特征、为何判定(可选,旧输出以 default 兜底)
    #[serde(default)]
    pub analysis: String,
}

impl LlmVerdict {
    pub fn is_block(&self) -> bool {
        self.verdict.eq_ignore_ascii_case("block")
    }
}

/// provider 无关的统一接口。编排层只持有 `Arc<dyn LlmProvider>`。
///
/// 扩展点:内置仅提供配置驱动的 OpenAI 兼容 provider。
/// 要接入异形端点(非 OpenAI 兼容的请求/响应格式),在外部实现本 trait 并在 from_config 注册即可,无需改动编排层。
#[async_trait::async_trait]
pub trait LlmProvider: Send + Sync {
    /// 对可疑请求做二级研判。
    async fn adjudicate(&self, summary: &RequestSummary) -> anyhow::Result<LlmVerdict>;
    /// provider 名称(用于事件详情 / 日志,如 "openai_compat")
    fn name(&self) -> &str;
}

/// WAF 研判用的系统提示。各 provider 共用,作为稳定前缀(支持缓存的 provider 可缓存它)。
pub const SYSTEM_PROMPT: &str = "\
You are a web application firewall (WAF) security analyst. \
You receive a summary of a single HTTP request that a rule engine flagged as suspicious. \
Decide whether it is a genuine attack that should be blocked, or benign traffic that should be allowed. \
Consider SQL injection, XSS, path traversal, command injection, SSRF, and reconnaissance/scanning. \
Be precise: do not block legitimate traffic that merely resembles an attack. \
Respond ONLY with a JSON object matching the required schema: \
verdict is \"block\" or \"allow\"; threat_type is a short label (e.g. \"SQLi\", \"XSS\", \"none\"); \
confidence is a number from 0 to 1; reason is one concise sentence; \
analysis is 2-3 sentences giving your detailed rationale (what features were hit, why the verdict).";

/// 构造发送给模型的用户消息:精简请求特征,不发全量 body。
pub fn build_user_content(summary: &RequestSummary) -> String {
    // body 已在代理层截断;此处再兜底截断,控制 token。
    let body_snippet: String = summary.body.chars().take(1000).collect();
    let headers_snippet: String = summary.headers.chars().take(800).collect();
    format!(
        "HTTP request to evaluate:\n\
         method: {}\n\
         path: {}\n\
         query: {}\n\
         user_agent: {}\n\
         headers (may be truncated): {}\n\
         client_ip: {}\n\
         body (may be truncated): {}",
        summary.method,
        summary.path,
        summary.query,
        summary.user_agent,
        headers_snippet,
        summary.client_ip,
        body_snippet,
    )
}

/// 从模型文本输出中宽松解析出 `LlmVerdict`。
/// 优先整体解析;失败则截取第一个 `{...}` 再解析(兼容未严格遵守结构化输出的本地模型)。
pub fn parse_verdict(text: &str) -> anyhow::Result<LlmVerdict> {
    let trimmed = text.trim();
    if let Ok(v) = serde_json::from_str::<LlmVerdict>(trimmed) {
        return Ok(v);
    }
    if let (Some(start), Some(end)) = (trimmed.find('{'), trimmed.rfind('}')) {
        if end > start {
            let slice = &trimmed[start..=end];
            if let Ok(v) = serde_json::from_str::<LlmVerdict>(slice) {
                return Ok(v);
            }
        }
    }
    anyhow::bail!("无法从模型输出解析裁决 JSON: {}", trimmed)
}
