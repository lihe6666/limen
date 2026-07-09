//! 离线评测:用 BlazeHTTP 风格的原始 HTTP 请求样本(*.black 攻击 / *.white 正常)
//! 跑一级规则引擎,输出检出率/误报率/准确率基线与误报驱动规则,供规则迭代对照。
//! 入口:`limen eval [样本目录]`,默认 testdata/blazehttp。

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::Context;
use crate::config::Config;

use crate::engine::verdict::Verdict;
use crate::engine::{LlmAdjudicator, NgramClassifier, RequestSummary, RuleEngine};
use crate::proxy::MAX_INSPECT_BODY;

const DEFAULT_SAMPLE_DIR: &str = "testdata/blazehttp";
const REPORT_DIR: &str = "target/eval";

pub async fn run(args: Vec<String>) -> anyhow::Result<()> {
    let (llm_mode, dir) = {
        let mut llm = false;
        let mut d = DEFAULT_SAMPLE_DIR.to_string();
        for a in &args {
            if a == "--llm" {
                llm = true;
            } else if !a.starts_with('-') {
                d = a.clone();
            }
        }
        (llm, d)
    };
    let root = Path::new(&dir);
    anyhow::ensure!(
        root.is_dir(),
        "样本目录 {} 不存在。可从 https://github.com/chaitin/blazehttp 获取 testcases",
        dir
    );

    // 阈值与线上一致:优先读 config.toml,缺省时 Config::default 兜底
    let cfg = Config::load("config.toml")?;
    let (block_th, susp_th) = (
        cfg.detection.block_threshold,
        cfg.detection.suspicious_threshold,
    );

    // ngram 分类器(可选):加载失败降级为不启用
    let ngram = cfg
        .detection
        .ngram_model
        .as_ref()
        .and_then(|path| match NgramClassifier::load(path) {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("警告: ngram 模型加载失败({path}): {e},跳过第二层");
                None
            }
        });
    let ngram_threshold = cfg.detection.ngram_threshold;

    let mut files = Vec::new();
    collect_samples(root, &mut files)?;
    anyhow::ensure!(!files.is_empty(), "{} 下没有 *.black / *.white 样本", dir);
    files.sort(); // 遍历顺序与文件系统无关,报告可复现

    let engine = RuleEngine::new();
    let mut stats = Stats::default();
    // (类别, 模式) → 命中过的白样本数,误报调参的直接依据
    let mut white_hit_rules: HashMap<(String, String), u32> = HashMap::new();
    // 黑样本主威胁类别分布
    let mut black_threats: HashMap<String, u32> = HashMap::new();
    let mut missed_black: Vec<(PathBuf, u32)> = Vec::new();
    let mut fp_white: Vec<(PathBuf, u32, String)> = Vec::new();
    let mut susp_samples: Vec<SuspEntry> = Vec::new();
    let mut inspect_time = Duration::ZERO;

    for path in &files {
        let is_black = path.extension().is_some_and(|e| e == "black");
        let bytes = std::fs::read(path)?;
        let Some(summary) = parse_sample(&bytes) else {
            stats.parse_failed += 1;
            continue;
        };

        let t = Instant::now();
        let det = engine.inspect(&summary);
        inspect_time += t.elapsed();

        let verdict = det.to_verdict(block_th, susp_th);

        // ngram 第二层提升:规则判 Allow 但 ngram 得分高 → 视为命中
        let elevated = if matches!(verdict, Verdict::Allow) {
            if let Some(ref ngram_cls) = ngram {
                let score = ngram_cls.score_parts(
                    &summary.method, &summary.path, &summary.query, &summary.body,
                );
                score >= ngram_threshold
            } else {
                false
            }
        } else {
            false
        };

        // 规则六格统计保持原口径(不受 ngram 提升影响)
        stats.count(is_black, &verdict);

        if elevated {
            if is_black {
                stats.ngram_elevated_black += 1;
            } else {
                stats.ngram_elevated_white += 1;
            }
        }

        if matches!(verdict, Verdict::Suspicious { .. }) {
            susp_samples.push(SuspEntry {
                path: path.clone(),
                is_black,
                summary: summary.clone(),
            });
        }
        if elevated {
            susp_samples.push(SuspEntry {
                path: path.clone(),
                is_black,
                summary: summary.clone(),
            });
        }

        if is_black {
            match verdict {
                Verdict::Allow => missed_black.push((path.clone(), det.score)),
                _ => {
                    let threat = det.primary_threat().unwrap_or_else(|| "unknown".into());
                    *black_threats.entry(threat).or_insert(0) += 1;
                }
            }
        } else {
            for hit in &det.hits {
                *white_hit_rules
                    .entry((hit.category.clone(), hit.pattern.clone()))
                    .or_insert(0) += 1;
            }
            if let Verdict::Block { .. } = verdict {
                fp_white.push((path.clone(), det.score, det.reasons().join("; ")));
            }
        }
    }

    write_detail_files(&missed_black, &fp_white)?;
    print_report(
        &dir,
        block_th,
        susp_th,
        &stats,
        &white_hit_rules,
        &black_threats,
        inspect_time,
        ngram.is_some(),
    );

    if llm_mode {
        run_llm_eval(&cfg, &stats, &susp_samples).await?;
    }

    Ok(())
}

/// 灰色样本条目:被规则引擎判为 Suspicious 后送 LLM 研判。
#[allow(dead_code)]
struct SuspEntry {
    path: PathBuf,
    is_black: bool,
    summary: RequestSummary,
}

/// 六格计数:黑/白 × Block/Suspicious/Allow,外加 ngram 提升计数。
#[derive(Default)]
struct Stats {
    black_block: u32,
    black_susp: u32,
    black_allow: u32,
    white_block: u32,
    white_susp: u32,
    white_allow: u32,
    ngram_elevated_black: u32,
    ngram_elevated_white: u32,
    parse_failed: u32,
}

impl Stats {
    fn count(&mut self, is_black: bool, v: &Verdict) {
        let slot = match (is_black, v) {
            (true, Verdict::Block { .. }) => &mut self.black_block,
            (true, Verdict::Suspicious { .. }) => &mut self.black_susp,
            (true, Verdict::Allow) => &mut self.black_allow,
            (false, Verdict::Block { .. }) => &mut self.white_block,
            (false, Verdict::Suspicious { .. }) => &mut self.white_susp,
            (false, Verdict::Allow) => &mut self.white_allow,
        };
        *slot += 1;
    }

    fn black_total(&self) -> u32 {
        self.black_block + self.black_susp + self.black_allow
    }
    fn white_total(&self) -> u32 {
        self.white_block + self.white_susp + self.white_allow
    }
}

/// LLM 二级研判评测:对规则引擎判为 Suspicious 的灰色样本逐条调用 LLM,
/// 统计灰色地带的消解质量(黑/白 × Block/Allow 四格)。
async fn run_llm_eval(
    cfg: &Config,
    stats: &Stats,
    susp_samples: &[SuspEntry],
) -> anyhow::Result<()> {
    tracing::info!("LLM 模式:构造二级研判层...");
    let client = reqwest::Client::builder()
        .build()
        .context("构建 HTTP 客户端失败")?;
    let adjudicator = LlmAdjudicator::from_config(&cfg.llm, client)
        .context("LLM 研判初始化失败,请检查 config.toml 的 [llm] 和 API key 环境变量")?;

    let mut susp_black_llm_block: u32 = 0;
    let mut susp_black_llm_allow: u32 = 0;
    let mut susp_white_llm_block: u32 = 0;
    let mut susp_white_llm_allow: u32 = 0;
    let mut llm_failures: u32 = 0;
    let mut llm_time = Duration::ZERO;

    let total = susp_samples.len();
    for (i, entry) in susp_samples.iter().enumerate() {
        let t = Instant::now();
        let decision = adjudicator.adjudicate(&entry.summary).await;
        llm_time += t.elapsed();

        if decision.source.contains("(fail)") {
            llm_failures += 1;
        }

        match (entry.is_black, decision.block) {
            (true, true) => susp_black_llm_block += 1,
            (true, false) => susp_black_llm_allow += 1,
            (false, true) => susp_white_llm_block += 1,
            (false, false) => susp_white_llm_allow += 1,
        }

        if (i + 1) % 25 == 0 {
            tracing::info!("LLM 研判进度: {}/{}", i + 1, total);
        }
    }

    print_llm_report(stats, susp_black_llm_block, susp_black_llm_allow, susp_white_llm_block, susp_white_llm_allow, llm_failures, llm_time, total);
    Ok(())
}

/// 递归收集 *.black / *.white 文件。
fn collect_samples(dir: &Path, out: &mut Vec<PathBuf>) -> anyhow::Result<()> {
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        if path.is_dir() {
            collect_samples(&path, out)?;
        } else if path.extension().is_some_and(|e| e == "black" || e == "white") {
            out.push(path);
        }
    }
    Ok(())
}

/// 把原始 HTTP 请求解析成引擎入参。
/// 在字节层面切分头/体,body 截断与 proxy 的 MAX_INSPECT_BODY 对齐,
/// 保证评测结果代表线上行为。格式不像请求的返回 None。
fn parse_sample(bytes: &[u8]) -> Option<RequestSummary> {
    // 头/体以首个空行分隔;兼容 \r\n 与 \n
    let (head_bytes, body_bytes) = match find_blank_line(bytes) {
        Some((head_end, body_start)) => (&bytes[..head_end], &bytes[body_start..]),
        None => (bytes, &[][..]),
    };
    let head = String::from_utf8_lossy(head_bytes);
    let mut lines = head.lines();

    // 请求行:METHOD SP target SP version
    let request_line = lines.next()?;
    let mut parts = request_line.split_whitespace();
    let method = parts.next()?.to_string();
    let target = parts.next()?;
    let version = parts.next()?;
    if !method.chars().all(|c| c.is_ascii_uppercase()) || !version.starts_with("HTTP/") {
        return None;
    }
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target.to_string(), String::new()),
    };

    let mut user_agent = String::new();
    let mut header_lines: Vec<String> = Vec::new();
    for header_line in lines {
        if let Some((name, value)) = header_line.split_once(':') {
            let name_trimmed = name.trim();
            if name_trimmed.eq_ignore_ascii_case("user-agent") {
                user_agent = value.trim().to_string();
            } else {
                header_lines.push(format!("{}: {}", name_trimmed, value.trim()));
            }
        }
    }
    let headers = header_lines.join("\n");

    let end = body_bytes.len().min(MAX_INSPECT_BODY);
    let body = String::from_utf8_lossy(&body_bytes[..end]).into_owned();

    Some(RequestSummary {
        method,
        path,
        query,
        user_agent,
        body,
        headers,
        client_ip: "0.0.0.0".to_string(),
    })
}

/// 返回首个空行的 (头结束偏移, 体起始偏移)。
fn find_blank_line(bytes: &[u8]) -> Option<(usize, usize)> {
    let crlf = bytes.windows(4).position(|w| w == b"\r\n\r\n");
    let lf = bytes.windows(2).position(|w| w == b"\n\n");
    match (crlf, lf) {
        (Some(c), Some(l)) if c <= l => Some((c, c + 4)),
        (_, Some(l)) => Some((l, l + 2)),
        (Some(c), None) => Some((c, c + 4)),
        (None, None) => None,
    }
}

/// LLM 二级研判报告:四格统计、消解比例、失败数、耗时。
fn print_llm_report(
    stats: &Stats,
    susp_black_llm_block: u32,
    susp_black_llm_allow: u32,
    susp_white_llm_block: u32,
    susp_white_llm_allow: u32,
    llm_failures: u32,
    llm_time: Duration,
    total: usize,
) {
    // 送 LLM 的样本总数 = 四格行和(规则 Suspicious + ngram 提升,统一处理)
    let susp_black_total = susp_black_llm_block + susp_black_llm_allow;
    let susp_white_total = susp_white_llm_block + susp_white_llm_allow;
    println!();
    println!("== LLM 二级研判(灰色地带:规则 Suspicious + ngram 提升)==");
    println!(
        "送检黑样本: {}(其中规则 {} + ngram 提升 {})  送检白样本: {}(规则 {} + ngram 提升 {})",
        susp_black_total,
        stats.black_susp,
        susp_black_total.saturating_sub(stats.black_susp),
        susp_white_total,
        stats.white_susp,
        susp_white_total.saturating_sub(stats.white_susp),
    );
    println!();
    println!("            LLM Block   LLM Allow");
    println!(
        "  灰色黑    {:>8}   {:>8}",
        susp_black_llm_block, susp_black_llm_allow
    );
    println!(
        "  灰色白    {:>8}   {:>8}",
        susp_white_llm_block, susp_white_llm_allow
    );
    println!();

    let llm_recall = pct(susp_black_llm_block, susp_black_total);
    let llm_fpr = pct(susp_white_llm_block, susp_white_total);

    println!(
        "LLM 拦截送检黑样本比例: {llm_recall:.2}% ({susp_black_llm_block}/{susp_black_total})"
    );
    println!(
        "LLM 误拦送检白样本比例: {llm_fpr:.2}% ({susp_white_llm_block}/{susp_white_total})"
    );
    println!("LLM 调用失败数: {llm_failures}");
    if total > 0 {
        let avg_ms = llm_time.as_secs_f64() * 1000.0 / total as f64;
        println!("平均每样本 LLM 耗时: {:.1} ms", avg_ms);
    }

    let nb = stats.black_total();
    let nw = stats.white_total();
    let final_tp = stats.black_block + susp_black_llm_block;
    let final_fp = stats.white_block + susp_white_llm_block;

    println!();
    println!("== 端到端(规则+LLM)==");
    println!(
        "最终检出率: {:.2}% ({final_tp}/{nb})",
        pct(final_tp, nb)
    );
    println!(
        "最终误报率: {:.2}% ({final_fp}/{nw})",
        pct(final_fp, nw)
    );
}

fn write_detail_files(
    missed_black: &[(PathBuf, u32)],
    fp_white: &[(PathBuf, u32, String)],
) -> anyhow::Result<()> {
    std::fs::create_dir_all(REPORT_DIR)?;

    let mut f = std::fs::File::create(format!("{REPORT_DIR}/missed_black.txt"))?;
    writeln!(f, "# 漏报的黑样本(得分未达 suspicious 阈值),共 {} 条", missed_black.len())?;
    for (path, score) in missed_black {
        writeln!(f, "{}\tscore={}", path.display(), score)?;
    }

    let mut f = std::fs::File::create(format!("{REPORT_DIR}/fp_white.txt"))?;
    writeln!(f, "# 被误拦截的白样本(得分达 block 阈值),共 {} 条", fp_white.len())?;
    for (path, score, reasons) in fp_white {
        writeln!(f, "{}\tscore={}\t{}", path.display(), score, reasons)?;
    }
    Ok(())
}

fn print_report(
    dir: &str,
    block_th: u32,
    susp_th: u32,
    stats: &Stats,
    white_hit_rules: &HashMap<(String, String), u32>,
    black_threats: &HashMap<String, u32>,
    inspect_time: Duration,
    ngram_configured: bool,
) {
    let (nb, nw) = (stats.black_total(), stats.white_total());
    println!("== Limen 规则引擎评测(BlazeHTTP)==");
    println!("样本目录: {dir}");
    println!("阈值: block={block_th}, suspicious={susp_th}");
    println!("黑样本: {nb}  白样本: {nw}  解析失败跳过: {}", stats.parse_failed);
    println!();
    println!("            Block   Suspicious   Allow");
    println!(
        "  黑样本  {:>7} {:>10} {:>7}   (Block=直接拦截, Suspicious=送LLM, Allow=漏报)",
        stats.black_block, stats.black_susp, stats.black_allow
    );
    println!(
        "  白样本  {:>7} {:>10} {:>7}   (Block=误报, Suspicious=LLM负载, Allow=正确放行)",
        stats.white_block, stats.white_susp, stats.white_allow
    );
    println!();

    print_metrics(
        "严格口径(仅 Block 算拦截)",
        stats.black_block,
        stats.white_block,
        nb,
        nw,
    );
    print_metrics(
        "宽松口径(Block+Suspicious 都算命中,假设 LLM 研判完美)",
        stats.black_block + stats.black_susp,
        stats.white_block + stats.white_susp,
        nb,
        nw,
    );

    // 三级漏斗
    if ngram_configured {
        let tier1_black = stats.black_block;
        let tier1_white = stats.white_block;
        let tier2_black = stats.ngram_elevated_black;
        let tier2_white = stats.ngram_elevated_white;
        let tier2_total = tier2_black + tier2_white;
        let two_tier_tp = tier1_black + tier2_black;
        let two_tier_fp = tier1_white + tier2_white;
        let rules_susp_total = stats.black_susp + stats.white_susp;
        let combined_susp_total = rules_susp_total + tier2_total;

        println!("== 三级漏斗(规则 → ngram → LLM) ==");
        println!(
            "  Tier1 规则直接 Block  黑{tier1_black:>7}  白{tier1_white:>7}"
        );
        println!(
            "  Tier2 ngram 从 Allow 提升  黑{tier2_black:>7}  白{tier2_white:>7}"
        );
        println!(
            "  二级合计送检(Suspicious): 规则{rules_susp_total} + ngram提升{tier2_total} = {combined_susp_total} 条(黑{} 白{})",
            stats.black_susp + tier2_black,
            stats.white_susp + tier2_white,
        );
        println!("  其中 Tier3 LLM: 见 --llm 四格报告");
        println!();

        print_metrics(
            "规则+ngram 两级口径",
            two_tier_tp,
            two_tier_fp,
            nb,
            nw,
        );
    } else {
        println!("== 三级漏斗(规则 → ngram → LLM) ==");
        println!("  (未配置 ngram_model,跳过第二层)");
        println!();
    }

    // 白样本误报驱动 Top 15
    let mut drivers: Vec<_> = white_hit_rules.iter().collect();
    drivers.sort_by(|a, b| b.1.cmp(a.1));
    println!("白样本命中规则 Top 15(误报/LLM 负载驱动):");
    for ((category, pattern), n) in drivers.iter().take(15) {
        println!("  {n:>6}  [{category}] {pattern:?}");
    }
    if drivers.is_empty() {
        println!("  (无)");
    }
    println!();

    // 黑样本命中类别分布
    let mut threats: Vec<_> = black_threats.iter().collect();
    threats.sort_by(|a, b| b.1.cmp(a.1));
    println!("被检出黑样本的主威胁分布:");
    for (threat, n) in threats {
        println!("  {n:>6}  {threat}");
    }
    println!();

    let total = (nb + nw) as f64;
    let us = inspect_time.as_secs_f64() * 1e6;
    if total > 0.0 && us > 0.0 {
        println!(
            "性能: inspect 总耗时 {:.2} ms,平均 {:.1} µs/请求,吞吐 {:.0} req/s",
            us / 1e3,
            us / total,
            total / inspect_time.as_secs_f64()
        );
    }
    println!("明细: {REPORT_DIR}/missed_black.txt, {REPORT_DIR}/fp_white.txt");
}

fn print_metrics(title: &str, tp: u32, fp: u32, nb: u32, nw: u32) {
    let fnn = nb - tp; // 漏报
    let recall = pct(tp, nb);
    let fp_rate = pct(fp, nw);
    let precision = pct(tp, tp + fp);
    let accuracy = pct(tp + (nw - fp), nb + nw);
    let f1 = if tp == 0 {
        0.0
    } else {
        let p = tp as f64 / (tp + fp) as f64;
        let r = tp as f64 / nb as f64;
        2.0 * p * r / (p + r)
    };
    println!("{title}:");
    println!(
        "  检出率 {recall:.2}%(漏报 {fnn})  误报率 {fp_rate:.3}%(误报 {fp})  精确率 {precision:.2}%  准确率 {accuracy:.2}%  F1 {f1:.3}"
    );
    println!();
}

fn pct(num: u32, den: u32) -> f64 {
    if den == 0 {
        0.0
    } else {
        num as f64 / den as f64 * 100.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_get_with_query() {
        let raw = b"GET /a/b?x=1&y=2 HTTP/1.1\r\nHost: h\r\nUser-Agent: sqlmap/1.7\r\n\r\n";
        let s = parse_sample(raw).unwrap();
        assert_eq!(s.method, "GET");
        assert_eq!(s.path, "/a/b");
        assert_eq!(s.query, "x=1&y=2");
        assert_eq!(s.user_agent, "sqlmap/1.7");
        assert_eq!(s.body, "");
        assert_eq!(s.headers, "Host: h");
    }

    #[test]
    fn parse_post_with_body_lf_only() {
        let raw = b"POST /login HTTP/1.1\nhost: h\nuser-agent: UA\n\nuser=admin&pass=1";
        let s = parse_sample(raw).unwrap();
        assert_eq!(s.method, "POST");
        assert_eq!(s.path, "/login");
        assert_eq!(s.query, "");
        assert_eq!(s.user_agent, "UA");
        assert_eq!(s.body, "user=admin&pass=1");
        assert_eq!(s.headers, "host: h");
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(parse_sample(b"").is_none());
        assert!(parse_sample(b"not an http request").is_none());
        assert!(parse_sample(b"<html>oops</html>").is_none());
    }
}
