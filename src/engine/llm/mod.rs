//! 二级 LLM 研判编排:按配置选出 provider,套上缓存 + 超时 + 降级。
//! provider 无关 —— 换厂商只改配置,不动这里。

mod openai_compat;
pub mod provider;

use std::sync::Arc;
use std::time::Duration;

use moka::future::Cache;

use crate::config::LlmConfig;
use crate::engine::verdict::RequestSummary;
use provider::LlmProvider;

/// 研判结论(编排层输出,已应用缓存/超时/降级)。
#[derive(Debug, Clone)]
pub struct LlmDecision {
    pub block: bool,
    pub threat: String,
    pub reason: String,
    /// 裁决来源,如 "llm:openai_compat" / "llm:openai_compat(cached)" / "llm:openai_compat(fail)"
    pub source: String,
    /// LLM 详细判断依据(2-3 句);缓存命中/降级时为空串
    pub analysis: String,
}

pub struct LlmAdjudicator {
    provider: Arc<dyn LlmProvider>,
    provider_name: String,
    /// 缓存:请求特征 → 是否拦截(TTL 内相同请求不重复调 LLM)
    cache: Cache<String, bool>,
    timeout: Duration,
    /// true=fail_open(故障放行);false=fail_close(故障拦截)
    fail_open: bool,
}

impl LlmAdjudicator {
    /// 按配置构建。provider 未知或不支持时返回错误。
    pub fn from_config(cfg: &LlmConfig, client: reqwest::Client) -> anyhow::Result<Self> {
        let api_key = std::env::var(&cfg.api_key_env).unwrap_or_default();

        let provider: Arc<dyn LlmProvider> = match cfg.provider.as_str() {
            "openai_compat" => Arc::new(openai_compat::OpenAiCompatProvider::new(
                client,
                &cfg.base_url,
                &cfg.model,
                api_key,
            )),
            other => anyhow::bail!(
                "未知 LLM provider: {}。内置仅 openai_compat(配置驱动,兼容 OpenAI/DeepSeek/Ollama/vLLM/Groq 等);自定义端点请实现 LlmProvider trait。",
                other
            ),
        };

        let provider_name = provider.name().to_string();
        let cache = Cache::builder()
            .max_capacity(10_000)
            .time_to_live(Duration::from_secs(300))
            .build();

        Ok(Self {
            provider,
            provider_name,
            cache,
            timeout: Duration::from_millis(cfg.timeout_ms),
            fail_open: cfg.fail_mode != "fail_close",
        })
    }

    /// 对可疑请求研判。命中缓存直接返回;否则调 provider,套超时;出错/超时按降级策略处理。
    pub async fn adjudicate(&self, summary: &RequestSummary) -> LlmDecision {
        let key = cache_key(summary);

        if let Some(block) = self.cache.get(&key).await {
            return LlmDecision {
                block,
                threat: if block { "cached".into() } else { "none".into() },
                reason: "cached verdict".into(),
                source: format!("llm:{}(cached)", self.provider_name),
                analysis: String::new(),
            };
        }

        let fut = self.provider.adjudicate(summary);
        match tokio::time::timeout(self.timeout, fut).await {
            Ok(Ok(v)) => {
                let block = v.is_block();
                self.cache.insert(key, block).await;
                LlmDecision {
                    block,
                    threat: v.threat_type,
                    reason: format!("{} (置信度 {:.2})", v.reason, v.confidence),
                    source: format!("llm:{}", self.provider_name),
                    analysis: v.analysis,
                }
            }
            Ok(Err(e)) => {
                tracing::warn!(error = %e, provider = %self.provider_name, "LLM 研判失败,按 fail_mode 降级");
                self.fail_decision(format!("error: {e}"))
            }
            Err(_) => {
                tracing::warn!(provider = %self.provider_name, timeout_ms = ?self.timeout, "LLM 研判超时,按 fail_mode 降级");
                self.fail_decision("timeout".into())
            }
        }
    }

    fn fail_decision(&self, reason: String) -> LlmDecision {
        LlmDecision {
            block: !self.fail_open,
            threat: "unknown".into(),
            reason,
            source: format!("llm:{}(fail)", self.provider_name),
            analysis: String::new(),
        }
    }

    /// 只查缓存的快速裁决:命中返回 Some(是否拦截),未命中返回 None。advisory 旁路模式同步快查用。
    pub async fn cached_verdict(&self, summary: &RequestSummary) -> Option<bool> {
        self.cache.get(&cache_key(summary)).await
    }
}

/// 缓存键:请求关键特征拼接。相同攻击特征在 TTL 内只研判一次。
fn cache_key(s: &RequestSummary) -> String {
    let body: String = s.body.chars().take(512).collect();
    let headers: String = s.headers.chars().take(512).collect();
    format!("{}|{}|{}|{}|{}|{}", s.method, s.path, s.query, s.user_agent, headers, body)
}
