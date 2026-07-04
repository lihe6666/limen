//! Anthropic Claude provider:`POST /v1/messages`,鉴权头 `x-api-key`。
//! 用 `output_config.format`(json_schema)约束结构化输出;系统提示打 cache_control 降本。

use serde_json::json;

use super::provider::{
    build_user_content, output_schema, parse_verdict, LlmProvider, LlmVerdict, SYSTEM_PROMPT,
};
use crate::engine::verdict::RequestSummary;

const DEFAULT_BASE: &str = "https://api.anthropic.com";
const ANTHROPIC_VERSION: &str = "2023-06-01";

pub struct AnthropicProvider {
    client: reqwest::Client,
    base_url: String,
    model: String,
    api_key: String,
}

impl AnthropicProvider {
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
impl LlmProvider for AnthropicProvider {
    fn name(&self) -> &str {
        "anthropic"
    }

    async fn adjudicate(&self, summary: &RequestSummary) -> anyhow::Result<LlmVerdict> {
        let url = format!("{}/v1/messages", self.base_url);
        let body = json!({
            "model": self.model,
            "max_tokens": 256,
            "system": [{
                "type": "text",
                "text": SYSTEM_PROMPT,
                "cache_control": { "type": "ephemeral" }
            }],
            "messages": [{
                "role": "user",
                "content": build_user_content(summary)
            }],
            "output_config": {
                "format": { "type": "json_schema", "schema": output_schema() }
            }
        });

        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", ANTHROPIC_VERSION)
            .json(&body)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            anyhow::bail!("Anthropic API {}: {}", status, text);
        }

        let v: serde_json::Value = resp.json().await?;
        // content 是块数组;取第一个 text 块
        let text = v["content"]
            .as_array()
            .and_then(|blocks| {
                blocks
                    .iter()
                    .find(|b| b["type"] == "text")
                    .and_then(|b| b["text"].as_str())
            })
            .ok_or_else(|| anyhow::anyhow!("Anthropic 响应缺少 text 块: {}", v))?;

        parse_verdict(text)
    }
}
