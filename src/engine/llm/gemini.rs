//! Google Gemini provider:`POST {base_url}/models/{model}:generateContent?key=KEY`。
//! 用 `generationConfig.responseSchema` + `responseMimeType: application/json` 约束结构化输出。

use serde_json::json;

use super::provider::{
    build_user_content, output_schema, parse_verdict, LlmProvider, LlmVerdict, SYSTEM_PROMPT,
};
use crate::engine::verdict::RequestSummary;

const DEFAULT_BASE: &str = "https://generativelanguage.googleapis.com/v1beta";

pub struct GeminiProvider {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: String,
}

impl GeminiProvider {
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
impl LlmProvider for GeminiProvider {
    fn name(&self) -> &str {
        "gemini"
    }

    async fn adjudicate(&self, summary: &RequestSummary) -> anyhow::Result<LlmVerdict> {
        let url = format!(
            "{}/models/{}:generateContent?key={}",
            self.base_url, self.model, self.api_key
        );
        let body = json!({
            "systemInstruction": {
                "parts": [{ "text": SYSTEM_PROMPT }]
            },
            "contents": [{
                "role": "user",
                "parts": [{ "text": build_user_content(summary) }]
            }],
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": output_schema()
            }
        });

        let resp = self.client.post(&url).json(&body).send().await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Gemini API {}: {}", status, text);
        }

        let v: serde_json::Value = resp.json().await?;
        let text = v["candidates"][0]["content"]["parts"][0]["text"]
            .as_str()
            .ok_or_else(|| anyhow::anyhow!("Gemini 响应缺少 parts[0].text: {}", v))?;

        parse_verdict(text)
    }
}
