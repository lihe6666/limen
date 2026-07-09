//! 代理 → TUI 的事件类型。代理每处理一个请求就通过 mpsc channel 发一个 `WafEvent`。

use std::time::{SystemTime, UNIX_EPOCH};

/// 对一个请求采取的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// 放行(规则未命中或分数低于可疑阈值)
    Allowed,
    /// 可疑:规则未达拦截线,已(或将)送 LLM 研判
    Suspicious,
    /// 拦截
    Blocked,
}

impl Action {
    pub fn label(&self) -> &'static str {
        match self {
            Action::Allowed => "ALLOW",
            Action::Suspicious => "SUSPECT",
            Action::Blocked => "BLOCK",
        }
    }
}

/// 一次请求处理的事件记录。
#[derive(Debug, Clone)]
pub struct WafEvent {
    /// 处理时刻的 UTC HH:MM:SS
    pub time: String,
    pub client_ip: String,
    pub method: String,
    pub path: String,
    pub action: Action,
    /// 规则引擎分数(放行为 0)
    pub score: u32,
    /// 主威胁类别(拦截/可疑时有)
    pub threat: Option<String>,
    /// 转发后的源站状态码(放行/可疑时有)
    pub status: Option<u16>,
    /// 命中原因 / 裁决来源(如 "rules" / "llm:openai_compat")
    pub detail: String,
}

/// 取当前 UTC 时间的 HH:MM:SS(避免引入 chrono)。
pub fn now_hms() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let s = secs % 86_400;
    format!("{:02}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
}
