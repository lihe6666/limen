//! 检测引擎:一级规则引擎(rules)+ 裁决类型(verdict)+ 二级 LLM 研判(llm)。

pub mod llm;
pub mod rules;
pub mod verdict;

pub use llm::LlmAdjudicator;
pub use rules::RuleEngine;
pub use verdict::{RequestSummary, Verdict};
