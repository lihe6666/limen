//! 反向代理核心:接收请求 → 检测流水线 → 转发源站 / 拦截。
//! 流水线:黑名单短路 → 已知路径直通 → 一级规则引擎 → 二级 LLM 研判(可疑时)。
//! 监控模式(enforce=false)下检测照跑、事件照记,但一律放行。

use axum::{
    body::Body,
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    response::Response,
    Router,
};
use std::fs::OpenOptions;
use std::io::Write;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::engine::{LlmAdjudicator, NgramClassifier, RequestSummary, RuleEngine, Verdict};
use crate::event::{now_hms, Action, WafEvent};
use crate::state::Controls;
use crate::storage::Storage;

pub(crate) const MAX_BODY_BYTES: usize = 10 * 1024 * 1024;
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
    pub gap_log: Option<String>,
    /// 启动时从配置解析好的可信代理 IP 列表
    pub trusted_proxies: Vec<std::net::IpAddr>,
    /// 取真实 IP 的头名,默认 "X-Forwarded-For"
    pub real_ip_header: String,
    /// LLM 后台异步并发上限
    pub llm_sem: std::sync::Arc<tokio::sync::Semaphore>,
    /// 直通白名单:命中则跳过三级检测(委托 Storage 的 SQLite + 内存缓存)
    pub storage: Option<std::sync::Arc<Storage>>,

    /// 配置的最大请求体字节数
    pub body_limit: usize,
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
    let headers = req.headers().clone();
    let client_ip = real_client_ip(
        addr.ip(),
        &headers,
        &state.trusted_proxies,
        &state.real_ip_header,
    );
    match pipeline(state, client_ip, req).await {
        Ok(resp) => resp,
        Err(err) => {
            tracing::error!(error = %err, "处理请求失败");
            error_response(StatusCode::BAD_GATEWAY, &format!("502 Bad Gateway: {err}"))
        }
    }
}

/// 从可信代理的转发头中提取真实客户端 IP,安全语义:
/// - 若 trusted 为空或 peer 不在 trusted 里:直接返回 peer.to_string(),不信任任何头
/// - 若 peer 在 trusted 里:
///   - X-Forwarded-For(大小写不敏感):取最右侧逗号分隔项(可信边缘代理实际观测到的直连 IP,
///     左侧项可能被客户端伪造),trim 后解析为 IpAddr,成功返回字符串,失败回退 peer
///   - 其他头(如 X-Real-IP):整值 trim 后解析为 IpAddr,成功返回字符串,失败回退 peer
pub(crate) fn real_client_ip(
    peer: std::net::IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &[std::net::IpAddr],
    header_name: &str,
) -> String {
    if trusted.is_empty() || !trusted.contains(&peer) {
        return peer.to_string();
    }
    let raw = match headers.get(header_name) {
        Some(v) => match v.to_str() {
            Ok(s) => s,
            Err(_) => return peer.to_string(),
        },
        None => return peer.to_string(),
    };
    if header_name.eq_ignore_ascii_case("x-forwarded-for") {
        raw.rsplit(',')
            .next()
            .map(|s| s.trim())
            .and_then(|s| s.parse::<std::net::IpAddr>().ok())
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| peer.to_string())
    } else {
        raw.trim()
            .parse::<std::net::IpAddr>()
            .ok()
            .map(|ip| ip.to_string())
            .unwrap_or_else(|| peer.to_string())
    }
}

async fn pipeline(
    state: SharedState,
    client_ip: String,
    req: Request,
) -> anyhow::Result<Response> {
    let (parts, body) = req.into_parts();
    let body_limit = if state.body_limit == 0 { MAX_BODY_BYTES } else { state.body_limit }; // 0 时用 10MB 兜底，否则按配置值
    let body_bytes = match axum::body::to_bytes(body, body_limit).await {
        Ok(b) => b,
        Err(_) => {
            return Ok(error_response(
                StatusCode::PAYLOAD_TOO_LARGE,
                &format!("413 Payload Too Large — body exceeds {} bytes", body_limit),
            ));
        }
    };

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

    // 0.5) 已知路径直通:命中白名单则跳过全部三级检测
    if let Some(ref st) = state.storage {
        if st.is_bypass(&summary.path) {
            let resp = forward(state.clone(), parts, body_bytes).await?;
            emit(
                &state,
                &summary,
                Action::Allowed,
                0,
                None,
                Some(resp.status().as_u16()),
                "已知路径直通".into(),
                "bypass",
            );
            return Ok(resp);
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
                match llm.cached_verdict(&summary).await {
                    Some(true) => {
                        // 已知恶意 → 立即拦(同步,无 LLM 延迟)
                        if let Some(ip) = ip_parsed {
                            if state.controls.record_block(ip) {
                                tracing::warn!(%client_ip, "同一 IP 多次拦截,已自动封禁");
                            }
                        }
                        block_or_monitor(
                            state, summary, parts, body_bytes, "llm-cached".into(), score,
                            format!("llm 缓存判定拦截 | trigger: {}", reasons.join("; ")),
                            "llm-cache",
                        )
                        .await
                    }
                    Some(false) => {
                        // 已知良性 → 放行
                        let resp = forward(state.clone(), parts, body_bytes).await?;
                        emit(
                            &state, &summary, Action::Suspicious, score, None,
                            Some(resp.status().as_u16()),
                            format!("llm 缓存判定放行 | trigger: {}", reasons.join("; ")),
                            "llm-cache",
                        );
                        Ok(resp)
                    }
                    None => {
                        // 首见可疑 → 立即放行 + 后台异步研判
                        let resp = forward(state.clone(), parts, body_bytes).await?;
                        let status = resp.status().as_u16();
                        emit(
                            &state, &summary, Action::Suspicious, score, None,
                            Some(status),
                            format!(
                                "advisory: 后台研判中 | trigger: {}",
                                reasons.join("; ")
                            ),
                            "advisory",
                        );
                        // 后台任务:有界并发,try_acquire 拿不到 permit 就跳过(不排队、不阻塞热路径)
                        match state.llm_sem.clone().try_acquire_owned() {
                            Ok(permit) => {
                                let st = state.clone();
                                let sm = summary.clone();
                                let ipp = ip_parsed;
                                tokio::spawn(async move {
                                    let _permit = permit;
                                    let decision = llm.adjudicate(&sm).await;
                                    if decision.block {
                                        if let Some(ip) = ipp {
                                            if st.controls.record_block(ip) {
                                                tracing::warn!(
                                                    %ip,
                                                    "advisory: LLM 判恶意累计,已自动封禁"
                                                );
                                            }
                                        }
                                        emit(
                                            &st, &sm, Action::Blocked, 0,
                                            Some(decision.threat.clone()), None,
                                            format!(
                                                "{}: {} | advisory 后台研判",
                                                decision.source, decision.reason
                                            ),
                                            "llm-async",
                                        );
                                        tracing::warn!(
                                            path = %sm.path,
                                            source = %decision.source,
                                            analysis = %decision.analysis,
                                            "advisory LLM 判定拦截(已缓存,拦后续同类)"
                                        );
                                    }
                                });
                            }
                            Err(_) => {
                                tracing::warn!(
                                    "LLM 后台并发已满,跳过本次 advisory 研判"
                                );
                            }
                        }
                        Ok(resp)
                    }
                }
            } else {
                let resp = forward(state.clone(), parts, body_bytes).await?;
                emit(
                    &state, &summary, Action::Suspicious, score, None,
                    Some(resp.status().as_u16()),
                    format!("rules: {}", reasons.join("; ")), "rules",
                );
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

    // 缺口捕获:规则漏判但被 ngram/LLM 等更高层级抓获,写入训练信号 JSONL
    if let Some(ref gap_path) = state.gap_log {
        if tier != "rules" && action != Action::Allowed {
            let body_snippet = summary.body.chars().take(512).collect::<String>();
            let json_line = serde_json::json!({
                "time": now_hms(),
                "client_ip": summary.client_ip,
                "method": summary.method,
                "path": summary.path,
                "query": summary.query,
                "body": body_snippet,
                "rule_score": score,
                "tier": tier,
                "action": action.label(),
                "threat": threat,
                "detail": detail,
            });
            match OpenOptions::new().create(true).append(true).open(gap_path) {
                Ok(mut f) => {
                    let _ = writeln!(f, "{}", json_line);
                }
                Err(e) => {
                    tracing::warn!(error = %e, path = %gap_path, "缺口捕获写文件失败");
                }
            }
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderMap;

    #[test]
    fn untrusted_peer_uses_peer_ip() {
        let peer = "1.2.3.4".parse::<std::net::IpAddr>().unwrap();
        let trusted: Vec<std::net::IpAddr> = vec![];
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "9.9.9.9".parse().unwrap());
        let result = real_client_ip(peer, &headers, &trusted, "x-forwarded-for");
        assert_eq!(result, "1.2.3.4");
    }

    #[test]
    fn trusted_proxy_xff_rightmost() {
        let peer = "127.0.0.1".parse::<std::net::IpAddr>().unwrap();
        let trusted: Vec<std::net::IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let mut headers = HeaderMap::new();
        headers.insert("x-forwarded-for", "5.5.5.5, 6.6.6.6".parse().unwrap());
        let result = real_client_ip(peer, &headers, &trusted, "x-forwarded-for");
        assert_eq!(result, "6.6.6.6");
    }

    #[test]
    fn trusted_proxy_missing_header_falls_back() {
        let peer = "127.0.0.1".parse::<std::net::IpAddr>().unwrap();
        let trusted: Vec<std::net::IpAddr> = vec!["127.0.0.1".parse().unwrap()];
        let headers = HeaderMap::new();
        let result = real_client_ip(peer, &headers, &trusted, "x-forwarded-for");
        assert_eq!(result, "127.0.0.1");
    }

    #[test]
    fn bypass_exact() {
        let storage = Storage::open(":memory:").unwrap();
        storage.add_bypass("/healthz", "test").unwrap();
        assert!(storage.is_bypass("/healthz"));
        assert!(!storage.is_bypass("/healthz2"));
    }

    #[test]
    fn bypass_prefix() {
        let storage = Storage::open(":memory:").unwrap();
        storage.add_bypass("/static/", "test").unwrap();
        assert!(storage.is_bypass("/static/a.js"));
        assert!(!storage.is_bypass("/api/x"));
    }

    #[test]
    fn bypass_empty() {
        let storage = Storage::open(":memory:").unwrap();
        assert!(!storage.is_bypass("/anything"));
    }
}
