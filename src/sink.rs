//! 请求处理事件的下游订阅者(EventSink)。
//! `proxy.rs::emit()` 只负责构造 `WafEvent` 并分发给已注册的 sink,不再直接
//! 耦合 TUI 通道 / tracing 日志 / 缺口捕获 / 审计落库这些具体逻辑。
//! 新增一种"记录发生了什么"的下游(如 Prometheus 指标、外部 SIEM),只需新增
//! 一个 EventSink 实现并注册进 `ProxyState::sinks`,不用改 `emit()` 本身。

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::engine::verdict::RequestSummary;
use crate::event::{Action, WafEvent};
use crate::storage::Storage;

/// 每条请求处理事件的订阅者。`summary` 提供 `WafEvent` 未携带的完整请求上下文
/// (query/body 等),供需要更多细节的 sink(如缺口捕获)使用。
pub trait EventSink: Send + Sync {
    fn on_event(&self, ev: &WafEvent, summary: &RequestSummary);
}

/// 转发到 TUI 仪表盘的 mpsc 通道。
pub struct TuiChannelSink {
    tx: mpsc::Sender<WafEvent>,
}

impl TuiChannelSink {
    pub fn new(tx: mpsc::Sender<WafEvent>) -> Self {
        Self { tx }
    }
}

impl EventSink for TuiChannelSink {
    fn on_event(&self, ev: &WafEvent, _summary: &RequestSummary) {
        let _ = self.tx.try_send(ev.clone());
    }
}

/// 落 tracing 日志(文件,TUI 模式下不能打印到 stdout)。
pub struct TracingSink;

impl EventSink for TracingSink {
    fn on_event(&self, ev: &WafEvent, _summary: &RequestSummary) {
        match ev.action {
            Action::Blocked => {
                tracing::warn!(tier = %ev.tier, client_ip = %ev.client_ip, method = %ev.method, path = %ev.path, score = ev.score, threat = ?ev.threat, detail = %ev.detail, "WAF 拦截");
            }
            Action::Suspicious => {
                tracing::info!(tier = %ev.tier, client_ip = %ev.client_ip, method = %ev.method, path = %ev.path, score = ev.score, threat = ?ev.threat, detail = %ev.detail, "WAF 送检/可疑");
            }
            Action::Allowed => {
                tracing::debug!(tier = %ev.tier, client_ip = %ev.client_ip, method = %ev.method, path = %ev.path, score = ev.score, threat = ?ev.threat, detail = %ev.detail, "WAF 放行");
            }
        }
    }
}

/// 缺口捕获:规则漏判但被 ngram/LLM 等更高层级抓获,写入训练信号 JSONL。
/// banned-ip/ratelimit 这两个 tier 跟"规则漏判"无关,排除,避免污染训练数据。
pub struct GapLogSink {
    path: String,
}

impl GapLogSink {
    pub fn new(path: String) -> Self {
        Self { path }
    }
}

impl EventSink for GapLogSink {
    fn on_event(&self, ev: &WafEvent, summary: &RequestSummary) {
        if ev.tier == "rules"
            || ev.tier == "banned-ip"
            || ev.tier == "ratelimit"
            || ev.action == Action::Allowed
        {
            return;
        }
        let body_snippet = summary.body.chars().take(512).collect::<String>();
        let json_line = serde_json::json!({
            "time": ev.time,
            "client_ip": ev.client_ip,
            "method": ev.method,
            "path": ev.path,
            "query": summary.query,
            "body": body_snippet,
            "rule_score": ev.score,
            "tier": ev.tier,
            "action": ev.action.label(),
            "threat": ev.threat,
            "detail": ev.detail,
        });
        match OpenOptions::new().create(true).append(true).open(&self.path) {
            Ok(mut f) => {
                let _ = writeln!(f, "{}", json_line);
            }
            Err(e) => {
                tracing::warn!(error = %e, path = %self.path, "缺口捕获写文件失败");
            }
        }
    }
}

/// SQLite 审计日志:每条事件落库。写入放进 `spawn_blocking`,不阻塞 async 请求处理线程。
pub struct AuditLogSink {
    storage: Arc<Storage>,
}

impl AuditLogSink {
    pub fn new(storage: Arc<Storage>) -> Self {
        Self { storage }
    }
}

impl EventSink for AuditLogSink {
    fn on_event(&self, ev: &WafEvent, _summary: &RequestSummary) {
        let storage = self.storage.clone();
        let ev = ev.clone();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = storage.append_audit_log(
                &ev.time,
                &ev.client_ip,
                &ev.method,
                &ev.path,
                ev.action.label(),
                ev.score,
                ev.threat.as_deref(),
                ev.status,
                &ev.detail,
                &ev.tier,
            ) {
                tracing::warn!(error = %e, "审计日志写入失败");
            }
        });
    }
}
