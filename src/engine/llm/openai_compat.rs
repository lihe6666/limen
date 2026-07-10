//! OpenAI 兼容 provider:`POST {base_url}/chat/completions`,鉴权头 `Authorization: Bearer`。
//! base_url 可配,一份实现覆盖 OpenAI / Ollama / vLLM / LocalAI / DeepSeek / Groq / Together 等。
//! 用 `response_format: json_object` 约束结构化输出;本地模型不支持时靠 parse_verdict 宽松兜底。

use serde_json::json;

use super::provider::{
    build_user_content, parse_verdict, LlmProvider, LlmVerdict, SYSTEM_PROMPT,
};
use crate::engine::verdict::RequestSummary;

const DEFAULT_BASE: &str = "https://api.openai.com/v1";

pub struct OpenAiCompatProvider {
    client: reqwest::Client,
    base_url: String,
    model: String,
    /// 可空:本地 Ollama 等不校验鉴权时留空,则不发 Authorization 头
    api_key: String,
}

impl OpenAiCompatProvider {
    pub fn new(client: reqwest::Client, base_url: &str, model: &str, api_key: String) -> Self {
        let base = if base_url.is_empty() {
            DEFAULT_BASE.to_string()
        } else {
            base_url.trim_end_matches('/').to_string()
        };
        Self {
            client,
            base_url: base,
            model: model.to_string(),
            api_key,
        }
    }
}

#[async_trait::async_trait]
impl LlmProvider for OpenAiCompatProvider {
    fn name(&self) -> &str {
        "openai_compat"
    }

    async fn adjudicate(&self, summary: &RequestSummary) -> anyhow::Result<LlmVerdict> {
        let url = format!("{}/chat/completions", self.base_url);
        let body = json!({
            "model": self.model,
            "max_tokens": 256,
            "messages": [
                { "role": "system", "content": SYSTEM_PROMPT },
                { "role": "user", "content": build_user_content(summary) }
            ],
            // 用 json_object 而非 json_schema:后者是 OpenAI 专属,DeepSeek 等兼容端点
            // 会拒绝("response_format type is unavailable")。系统提示已约束严格 JSON,
            // parse_verdict 亦有宽松兜底,足以覆盖各兼容端点。
            "response_format": { "type": "json_object" }
        });

        let mut req = self.client.post(&url).json(&body);
        if !self.api_key.is_empty() {
            req = req.bearer_auth(&self.api_key);
        }
        let resp = req.send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("OpenAI 兼容 API {}: {}", status, text);
        }

        let v: serde_json::Value = resp.json().await?;
        let text = v["choices"][0]["message"]["content"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("OpenAI 兼容响应缺少 message.content: {}", v))?;

        parse_verdict(text)
    }
}
