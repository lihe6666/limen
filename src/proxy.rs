//! 反向代理核心:接收请求 → 检测流水线 → 转发源站 / 拦截。
//! 流水线:黑名单短路 → 一级规则引擎 → 二级 LLM 研判(可疑时)。
//! 监控模式(enforce=false)下检测照跑、事件照记,但一律放行。

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    response::Response,
    Router,
};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::engine::{LlmAdjudicator, NgramClassifier, RequestSummary, RuleEngine, Verdict};
use crate::event::{now_hms, Action, WafEvent};
use crate::state::Controls;

const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
pub(crate) const MAX_INSPECT_BODY: usize = 16 * 1024;

pub struct ProxyState {
    pub client: reqwest::Client,
    pub upstream: String,
    pub engine: RuleEngine,
    pub block_threshold: u32,
    pub suspicious_threshold: u32,
    pub llm: Option<Arc<LlmAdjudicator>>,
    pub ngram: Option<NgramClassifier>,
    pub ngram_threshold: f32,
    pub controls: Arc<Controls>,
    pub tx: mpsc::Sender<WafEvent>,
}

pub type SharedState = Arc<ProxyState>;

pub fn router(state: SharedState) -> Router {
    Router::new().fallback(handle).with_state(state)
}

fn is_hop_by_hop(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

async fn handle(
    State(state): State<SharedState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    req: Request,
) -> Response {
    match pipeline(state, addr.ip().to_string(), req).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!(error = %err, "处理请求失败");
            error_response(StatusCode::BAD_GATEWAY, &format!("502 Bad Gateway: {err}"))
        }
    }
}

async fn pipeline(
    state: SharedState,
    client_ip: String,
    req: Request,
) -> anyhow::Result<Response> {
    let (parts, body) = req.into_parts();
    let body_bytes = axum::body::to_bytes(body, MAX_BODY_BYTES).await?;

    let inspect_body = {
        let end = body_bytes.len().min(MAX_INSPECT_BODY);
        String::from_utf8_lossy(&body_bytes[..end]).into_owned()
    };
    let mut user_agent = String::new();
    let mut header_lines: Vec<String> = Vec::new();
    for (name, value) in parts.headers.iter() {
        let name_str = name.as_str();
        let value_str = value.to_str().unwrap_or("");
        if name_str.eq_ignore_ascii_case("user-agent") {
            user_agent = value_str.to_string();
        } else {
            header_lines.push(format!("{}: {}", name_str, value_str));
        }
    }
    let headers = header_lines.join("\n");
    let summary = RequestSummary {
        method: parts.method.as_str().to_string(),
        path: parts.uri.path().to_string(),
        query: parts.uri.query().unwrap_or("").to_string(),
        user_agent,
        body: inspect_body,
        headers,
        client_ip: client_ip.clone(),
    };

    let ip_parsed: Option<IpAddr> = client_ip.parse().ok();

    // 0) 黑名单短路
    if let Some(ip) = ip_parsed {
        if state.controls.is_banned(&ip) {
            return block_or_monitor(
                state, summary, parts, body_bytes, "banned-ip".into(), 0,
                "IP 在黑名单".into(), "banned-ip",
            )
            .await;
        }
    }

    // 1) 一级规则引擎
    let detection = state.engine.inspect(&summary);
    let mut verdict = detection.to_verdict(state.block_threshold, state.suspicious_threshold);

    // 1.5) ngram 分类器二层提升:规则判 Allow 但 ngram 得分高 → 提升为 Suspicious
    if matches!(verdict, Verdict::Allow) {
        if let Some(ref ngram) = state.ngram {
            let score = ngram.score_parts(&summary.method, &summary.path, &summary.query, &summary.body);
            if score >= state.ngram_threshold {
                verdict = Verdict::Suspicious {
                    score: state.suspicious_threshold,
                    reasons: vec![format!("ngram classifier: {:.3}", score)],
                };
            }
        }
    }

    match verdict {
        Verdict::Block { score, threat, reasons } => {
            if let Some(ip) = ip_parsed {
                if state.controls.record_block(ip) {
                    tracing::warn!(%client_ip, "同一 IP 多次拦截,已自动封禁");
                }
            }
            block_or_monitor(state, summary, parts, body_bytes, threat, score, reasons.join("; "), "rules").await
        }
        Verdict::Suspicious { score, reasons } => {
            if let Some(llm) = state.llm.clone() {
                let decision = llm.adjudicate(&summary).await;
                if decision.block {
                    if let Some(ip) = ip_parsed {
                        if state.controls.record_block(ip) {
                            tracing::warn!(%client_ip, "同一 IP 多次拦截,已自动封禁");
                        }
                    }
                    tracing::warn!(
                        %client_ip, path = %summary.path, score,
                        source = %decision.source, reason = %decision.reason,
                        "LLM 研判判定拦截"
                    );
                    tracing::info!(
                        tier = "llm", analysis = %decision.analysis, reason = %decision.reason,
                        path = %summary.path, "LLM 研判详情"
                    );
                    let detail = format!("{}: {} | trigger: {}",
                        decision.source, decision.reason, reasons.join("; "));
                    block_or_monitor(
                        state, summary, parts, body_bytes, decision.threat, score,
                        detail, "llm",
                    )
                    .await
                } else {
                    let resp = forward(state.clone(), parts, body_bytes).await?;
                    tracing::info!(
                        tier = "llm", analysis = %decision.analysis, reason = %decision.reason,
                        path = %summary.path, "LLM 研判详情"
                    );
                    let detail = format!("{}: {} | trigger: {}",
                        decision.source, decision.reason, reasons.join("; "));
                    emit(&state, &summary, Action::Suspicious, score, None,
                        Some(resp.status().as_u16()),
                        detail, "llm");
                    Ok(resp)
                }
            } else {
                let resp = forward(state.clone(), parts, body_bytes).await?;
                emit(&state, &summary, Action::Suspicious, score, None,
                    Some(resp.status().as_u16()),
                    format!("rules: {}", reasons.join("; ")), "rules");
                Ok(resp)
            }
        }
        Verdict::Allow => {
            let resp = forward(state.clone(), parts, body_bytes).await?;
            emit(&state, &summary, Action::Allowed, 0, None,
                Some(resp.status().as_u16()), "rules".into(), "rules");
            Ok(resp)
        }
    }
}

/// 对"应拦截"的请求:enforce 模式返回 403;monitor 模式转发但记为"本应拦截"。
async fn block_or_monitor(
    state: SharedState,
    summary: RequestSummary,
    parts: axum::http::request::Parts,
    body_bytes: axum::body::Bytes,
    threat: String,
    score: u32,
    detail: String,
    tier: &str,
) -> anyhow::Result<Response> {
    if state.controls.enforce() {
        emit(&state, &summary, Action::Blocked, score, Some(threat), None, detail, tier);
        Ok(error_response(
            StatusCode::FORBIDDEN,
            "403 Forbidden — request blocked by WAF",
        ))
    } else {
        // 监控模式:放行,但事件标注"本应拦截",便于上线前调参
        let resp = forward(state.clone(), parts, body_bytes).await?;
        emit(
            &state, &summary, Action::Suspicious, score, Some(threat),
            Some(resp.status().as_u16()),
            format!("MONITOR(本应拦截): {}", detail),
            tier,
        );
        Ok(resp)
    }
}

async fn forward(
    state: SharedState,
    parts: axum::http::request::Parts,
    body_bytes: axum::body::Bytes,
) -> anyhow::Result<Response> {
    let path_and_query = parts
        .uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let url = format!("{}{}", state.upstream, path_and_query);

    let method = reqwest::Method::from_bytes(parts.method.as_str().as_bytes())?;
    let mut rb = state.client.request(method, &url);

    for (name, value) in parts.headers.iter() {
        let n = name.as_str();
        if is_hop_by_hop(n)
            || n.eq_ignore_ascii_case("host")
            || n.eq_ignore_ascii_case("content-length")
        {
            continue;
        }
        rb = rb.header(n, value.as_bytes());
    }
    rb = rb.body(body_bytes.to_vec());

    let upstream_resp = rb.send().await?;

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_bytes = upstream_resp.bytes().await?;

    let mut builder = Response::builder().status(status.as_u16());
    for (name, value) in resp_headers.iter() {
        let n = name.as_str();
        if is_hop_by_hop(n) || n.eq_ignore_ascii_case("content-length") {
            continue;
        }
        builder = builder.header(n, value.as_bytes());
    }
    Ok(builder.body(Body::from(resp_bytes))?)
}

fn emit(
    state: &SharedState,
    summary: &RequestSummary,
    action: Action,
    score: u32,
    threat: Option<String>,
    status: Option<u16>,
    detail: String,
    tier: &str,
) {
    let ev = WafEvent {
        time: now_hms(),
        client_ip: summary.client_ip.clone(),
        method: summary.method.clone(),
        path: summary.path.clone(),
        action,
        score,
        threat: threat.clone(),
        status,
        detail: detail.clone(),
        tier: tier.to_string(),
    };
    let _ = state.tx.try_send(ev);

    match action {
        Action::Blocked => {
            tracing::warn!(tier, client_ip = %summary.client_ip, method = %summary.method, path = %summary.path, score, threat = ?threat, detail = %detail, "WAF 拦截");
        }
        Action::Suspicious => {
            tracing::info!(tier, client_ip = %summary.client_ip, method = %summary.method, path = %summary.path, score, threat = ?threat, detail = %detail, "WAF 送检/可疑");
        }
        Action::Allowed => {
            tracing::debug!(tier, client_ip = %summary.client_ip, method = %summary.method, path = %summary.path, score, threat = ?threat, detail = %detail, "WAF 放行");
        }
    }
}

fn error_response(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Body::from(msg.to_string()))
        .unwrap()
}
