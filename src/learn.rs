//! 离线规则蒸馏:`limen learn`。
//! 读缺口样本(规则漏判、被 ngram/LLM 抓到的恶意 payload)→ 让 LLM 提议候选检测规则
//! → 用 BlazeHTTP 白样本做误报闸门校验 → 只输出通过校验的候选给人工审核。
//!
//! 安全定位:**只产候选、不自动改规则**。零误报是硬闸门——攻击者能影响学习输入,
//! 所以任何候选必须先过大规模可信白样本,人工审核后才手工采纳。

use std::collections::HashSet;
use std::io::Write;
use std::path::Path;

use serde::Deserialize;

use crate::config::Config;
use crate::eval::{collect_samples, parse_sample};

const DEFAULT_GAPS: &str = "gaps.jsonl";
const DEFAULT_WHITES: &str = "benchmarks/blazehttp";
const OUT_FILE: &str = "candidate_rules.txt";
const MAX_PAYLOADS_TO_LLM: usize = 50;

/// 缺口记录(gaps.jsonl 每行)。只取蒸馏需要的字段,其余忽略。
#[derive(Deserialize)]
struct GapRecord {
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    query: String,
    #[serde(default)]
    body: String,
}

/// LLM 提议的候选规则。
#[derive(Deserialize)]
struct Candidate {
    pattern: String,
    #[serde(default)]
    is_regex: bool,
    #[serde(default)]
    category: String,
    #[serde(default)]
    score: u32,
    #[serde(default)]
    rationale: String,
}

/// 校验后的候选 + 统计。
struct Scored {
    cand: Candidate,
    detect: u32, // 命中的 gap payload 数
    fp: u32,     // 命中的白样本数
    regex_ok: bool,
}

pub async fn run(args: Vec<String>) -> anyhow::Result<()> {
    let mut gaps_path = DEFAULT_GAPS.to_string();
    let mut whites_dir = DEFAULT_WHITES.to_string();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--whites" => {
                if let Some(v) = it.next() {
                    whites_dir = v.clone();
                }
            }
            s if !s.starts_with('-') => gaps_path = s.to_string(),
            _ => {}
        }
    }

    let cfg = Config::load("config.toml")?;

    // 1) 读缺口 payload(去重)
    let payloads = load_gap_payloads(&gaps_path)?;
    anyhow::ensure!(!payloads.is_empty(), "{} 无可用缺口样本", gaps_path);
    println!("读入 {} 条去重缺口 payload(取前 {} 条送 LLM)", payloads.len(), payloads.len().min(MAX_PAYLOADS_TO_LLM));

    // 2) LLM 提议候选规则
    let candidates = propose_rules(&cfg, &payloads[..payloads.len().min(MAX_PAYLOADS_TO_LLM)]).await?;
    anyhow::ensure!(!candidates.is_empty(), "LLM 未产出可解析的候选规则");
    println!("LLM 提议 {} 条候选,开始白样本误报闸门校验...", candidates.len());

    // 3) 误报闸门:加载白样本 haystack
    let whites = load_white_haystacks(Path::new(&whites_dir))?;
    println!("加载 {} 条白样本用于误报校验\n", whites.len());

    // 4) 逐条统计 detect / fp
    let mut scored: Vec<Scored> = candidates.into_iter().map(|c| score_candidate(c, &payloads, &whites)).collect();
    // 排序:先零误报优先(fp 升序),再检出多优先(detect 降序)
    scored.sort_by(|a, b| a.fp.cmp(&b.fp).then(b.detect.cmp(&a.detect)));

    // 5) 报告
    print_report(&scored);
    write_candidate_file(&scored)?;
    Ok(())
}

/// 读 gaps.jsonl,构造去重后的 payload 文本(path + query + body)。
fn load_gap_payloads(path: &str) -> anyhow::Result<Vec<String>> {
    let text = std::fs::read_to_string(path)
        .map_err(|e| anyhow::anyhow!("读 {} 失败: {}(先在 config 配 gap_log 采集,或指定路径)", path, e))?;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Ok(rec) = serde_json::from_str::<GapRecord>(line) else {
            continue; // 跳过坏行
        };
        let payload = format!("{} {} {}", rec.path, rec.query, rec.body);
        let _ = rec.method; // method 目前不用于 payload 文本
        if seen.insert(payload.clone()) {
            out.push(payload);
        }
    }
    Ok(out)
}

/// 让配置的 OpenAI 兼容端点提议候选规则。
async fn propose_rules(cfg: &Config, payloads: &[String]) -> anyhow::Result<Vec<Candidate>> {
    let base = if cfg.llm.base_url.is_empty() {
        "https://api.openai.com/v1".to_string()
    } else {
        cfg.llm.base_url.trim_end_matches('/').to_string()
    };
    let url = format!("{}/chat/completions", base);
    let api_key = std::env::var(&cfg.llm.api_key_env).unwrap_or_default();

    let system = "你是 WAF 规则工程师。下面是规则引擎漏判的恶意 HTTP payload(path query body 拼接)。\
请提议能命中这些攻击、但尽量不误伤正常流量的检测规则。\
只输出一个 JSON 对象 {\"rules\":[...]},数组每项为 \
{pattern(小写字符串或正则), is_regex(bool), category(如 SQLi/XSS/PathTraversal/InfoDisclosure/CommandInjection), \
score(40-100 整数,高置信给高分), rationale(一句中文说明)}。\
规则要具体,避免过于宽泛匹配到正常英文单词或常见参数名。";

    let mut user = String::from("漏判的恶意 payload 列表:\n");
    for (i, p) in payloads.iter().enumerate() {
        let snippet: String = p.chars().take(300).collect();
        user.push_str(&format!("{}. {}\n", i + 1, snippet));
    }

    let body = serde_json::json!({
        "model": cfg.llm.model,
        "max_tokens": 1500,
        "messages": [
            { "role": "system", "content": system },
            { "role": "user", "content": user }
        ],
        "response_format": { "type": "json_object" }
    });

    let client = reqwest::Client::builder().build()?;
    let mut req = client.post(&url).json(&body);
    if !api_key.is_empty() {
        req = req.bearer_auth(&api_key);
    }
    let resp = req.send().await?;
    if !resp.status().is_success() {
        let status = resp.status();
        let t = resp.text().await.unwrap_or_default();
        anyhow::bail!("规则生成 API {}: {}", status, t);
    }
    let v: serde_json::Value = resp.json().await?;
    let content = v["choices"][0]["message"]["content"]
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("LLM 响应缺少 message.content"))?;

    parse_candidates(content)
}

/// 从 LLM 文本里解析候选数组。优先整体解析 {"rules":[...]},失败则截取第一个 [ 到最后 ] 再试。
fn parse_candidates(text: &str) -> anyhow::Result<Vec<Candidate>> {
    #[derive(Deserialize)]
    struct Wrap {
        rules: Vec<Candidate>,
    }
    if let Ok(w) = serde_json::from_str::<Wrap>(text.trim()) {
        return Ok(w.rules);
    }
    if let (Some(s), Some(e)) = (text.find('['), text.rfind(']')) {
        if e > s {
            if let Ok(v) = serde_json::from_str::<Vec<Candidate>>(&text[s..=e]) {
                return Ok(v);
            }
        }
    }
    anyhow::bail!("无法从 LLM 输出解析候选规则 JSON")
}

/// 白样本归一 haystack(小写 path+query+body)。
fn load_white_haystacks(dir: &Path) -> anyhow::Result<Vec<String>> {
    anyhow::ensure!(dir.is_dir(), "白样本目录 {} 不存在", dir.display());
    let mut files = Vec::new();
    collect_samples(dir, &mut files)?;
    let mut out = Vec::new();
    for f in &files {
        if f.extension().is_some_and(|e| e == "white") {
            if let Some(s) = parse_sample(&std::fs::read(f)?) {
                out.push(format!("{} {} {}", s.path, s.query, s.body).to_lowercase());
            }
        }
    }
    Ok(out)
}

/// 对一个候选规则统计 detect(命中 gap 数)与 fp(命中白样本数)。
fn score_candidate(cand: Candidate, payloads: &[String], whites: &[String]) -> Scored {
    let pat_lower = cand.pattern.to_lowercase();
    if cand.is_regex {
        match regex::Regex::new(&format!("(?i){}", cand.pattern)) {
            Ok(re) => {
                let detect = payloads.iter().filter(|p| re.is_match(p)).count() as u32;
                let fp = whites.iter().filter(|w| re.is_match(w)).count() as u32;
                Scored { cand, detect, fp, regex_ok: true }
            }
            Err(_) => Scored { cand, detect: 0, fp: 0, regex_ok: false },
        }
    } else {
        let detect = payloads.iter().filter(|p| p.to_lowercase().contains(&pat_lower)).count() as u32;
        let fp = whites.iter().filter(|w| w.contains(&pat_lower)).count() as u32;
        Scored { cand, detect, fp, regex_ok: true }
    }
}

fn print_report(scored: &[Scored]) {
    println!("== 候选规则校验报告 ==\n");
    let (clean, dirty): (Vec<_>, Vec<_>) = scored
        .iter()
        .filter(|s| s.regex_ok)
        .partition(|s| s.fp == 0 && s.detect > 0);

    println!("【零误报候选(建议采纳)】{} 条", clean.len());
    print_rows(&clean);
    println!();
    println!("【有误报/无检出候选(需收紧,不建议直接用)】{} 条", dirty.len());
    print_rows(&dirty);

    let bad: Vec<_> = scored.iter().filter(|s| !s.regex_ok).collect();
    if !bad.is_empty() {
        println!("\n{} 条候选正则编译失败,已丢弃。", bad.len());
    }
}

fn print_rows(rows: &[&Scored]) {
    if rows.is_empty() {
        println!("  (无)");
        return;
    }
    println!("  {:<28} {:<16} {:>5} {:>7} {:>5}  说明", "pattern", "category", "score", "detect", "fp");
    for s in rows {
        let p: String = s.cand.pattern.chars().take(28).collect();
        println!(
            "  {:<28} {:<16} {:>5} {:>7} {:>5}  {}",
            p, s.cand.category, s.cand.score, s.detect, s.fp, s.cand.rationale
        );
    }
}

/// 把零误报候选写成可直接粘贴的 Rust 元组。
fn write_candidate_file(scored: &[Scored]) -> anyhow::Result<()> {
    let mut f = std::fs::File::create(OUT_FILE)?;
    writeln!(f, "// limen learn 产出:已过零误报校验的候选规则,待人工审核后手工粘贴进 rules.rs。")?;
    writeln!(f, "// 注意:零误报仅针对当前白样本集;采纳前请复核语义,并跑 `cargo run -- eval` 确认整体影响。")?;
    let mut n = 0;
    for s in scored.iter().filter(|s| s.regex_ok && s.fp == 0 && s.detect > 0) {
        if s.cand.is_regex {
            writeln!(
                f,
                "    // [正则] 命中 gap {} 条, 误报 0 —— {}\n    (r\"(?i){}\", \"{}\", {}),",
                s.detect, s.cand.rationale, s.cand.pattern, s.cand.category, s.cand.score
            )?;
        } else {
            writeln!(
                f,
                "    (\"{}\", \"{}\", {}),   // 命中 gap {} 条, 误报 0 —— {}",
                s.cand.pattern, s.cand.category, s.cand.score, s.detect, s.cand.rationale
            )?;
        }
        n += 1;
    }
    println!("\n{} 条零误报候选已写入 {}(待人工审核)", n, OUT_FILE);
    Ok(())
}
