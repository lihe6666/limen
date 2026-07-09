//! 裁决类型与检测流水线的公共数据结构。
//! 规则引擎(一级)和 LLM 研判(二级,阶段4)都产出这里定义的 `Verdict`。

/// 送检的请求摘要。规则引擎与 LLM 层共用;LLM 层只发这些精简特征,不发全量 body。
#[derive(Debug, Clone)]
pub struct RequestSummary {
    pub method: String,
    pub path: String,
    pub query: String,
    pub user_agent: String,
    /// UTF-8 有损解码后的请求体(可能被截断)
    pub body: String,
    /// 除 User-Agent 外所有请求头按 'name: value' 每行一条拼接,\n 分隔
    /// (UA 由扫描器规则单独处理)
    pub headers: String,
    pub client_ip: String,
}

/// 单条命中记录。
#[derive(Debug, Clone)]
pub struct Hit {
    /// 威胁类别,如 "SQLi" / "XSS" / "PathTraversal"
    pub category: String,
    /// 命中的模式(用于展示/审计)
    pub pattern: String,
    /// 该命中贡献的分数
    pub score: u32,
}

/// 一次检测的聚合结果。
#[derive(Debug, Clone, Default)]
pub struct Detection {
    pub score: u32,
    pub hits: Vec<Hit>,
}

impl Detection {
    /// 命中的威胁类别去重列表,取分数最高的类别作为主威胁。
    pub fn primary_threat(&self) -> Option<String> {
        self.hits
            .iter()
            .max_by_key(|h| h.score)
            .map(|h| h.category.clone())
    }

    pub fn reasons(&self) -> Vec<String> {
        self.hits
            .iter()
            .map(|h| format!("{}: {}", h.category, h.pattern))
            .collect()
    }

    /// 依据阈值把分数映射为裁决。
    pub fn to_verdict(&self, block_threshold: u32, suspicious_threshold: u32) -> Verdict {
        if self.score >= block_threshold {
            Verdict::Block {
                score: self.score,
                threat: self.primary_threat().unwrap_or_else(|| "unknown".into()),
                reasons: self.reasons(),
            }
        } else if self.score >= suspicious_threshold {
            Verdict::Suspicious {
                score: self.score,
                reasons: self.reasons(),
            }
        } else {
            Verdict::Allow
        }
    }
}

/// 检测流水线的最终裁决。
#[derive(Debug, Clone)]
pub enum Verdict {
    /// 放行
    Allow,
    /// 灰色地带:规则未达拦截线,但值得送 LLM 二级研判(阶段4)
    Suspicious { score: u32, reasons: Vec<String> },
    /// 拦截
    Block {
        score: u32,
        threat: String,
        reasons: Vec<String>,
    },
}
