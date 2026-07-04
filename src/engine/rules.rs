//! 一级规则引擎:本地、同步、零延迟。
//! 用 aho-corasick 做大规模字面量多模式匹配,配合少量结构化正则捕捉需要上下文的攻击特征。
//! 对 path/query/body 先做一次 URL 解码,以捕获百分号编码的 payload。

use aho_corasick::AhoCorasick;
use regex::Regex;

use super::verdict::{Detection, Hit, RequestSummary};

/// 字面量规则:(模式, 类别, 分数)。分数越高越接近"明确恶意"。
/// 高置信特征给到 100(默认即达 block 阈值);模糊特征给较低分,靠累加或 LLM 研判定性。
const LITERAL_RULES: &[(&str, &str, u32)] = &[
    // ---- SQL 注入 ----
    ("union select", "SQLi", 100),
    ("union all select", "SQLi", 100),
    ("information_schema", "SQLi", 80),
    ("' or '1'='1", "SQLi", 100),
    ("' or 1=1", "SQLi", 100),
    ("\" or \"1\"=\"1", "SQLi", 100),
    ("or 1=1--", "SQLi", 100),
    ("'; drop table", "SQLi", 100),
    ("; drop table", "SQLi", 90),
    ("sleep(", "SQLi", 70),
    ("benchmark(", "SQLi", 70),
    ("waitfor delay", "SQLi", 80),
    ("load_file(", "SQLi", 80),
    ("into outfile", "SQLi", 90),
    ("xp_cmdshell", "SQLi", 100),
    ("' --", "SQLi", 40),
    ("'--", "SQLi", 40),
    // ---- XSS ----
    ("<script", "XSS", 90),
    ("</script", "XSS", 60),
    ("javascript:", "XSS", 70),
    ("onerror=", "XSS", 80),
    ("onload=", "XSS", 70),
    ("onmouseover=", "XSS", 70),
    ("<svg", "XSS", 60),
    ("<iframe", "XSS", 70),
    ("document.cookie", "XSS", 80),
    ("alert(", "XSS", 40),
    ("String.fromCharCode", "XSS", 60),
    // ---- 路径穿越 / 本地文件包含 ----
    ("../", "PathTraversal", 50),
    ("..\\", "PathTraversal", 50),
    ("/etc/passwd", "PathTraversal", 90),
    ("/etc/shadow", "PathTraversal", 90),
    ("c:\\windows", "PathTraversal", 70),
    ("boot.ini", "PathTraversal", 70),
    ("php://filter", "PathTraversal", 90),
    ("file://", "PathTraversal", 60),
    // ---- 命令注入(用较具体的组合以降低误报) ----
    ("$(", "CommandInjection", 70),
    ("; cat ", "CommandInjection", 80),
    ("; ls ", "CommandInjection", 70),
    ("| nc ", "CommandInjection", 90),
    ("nc -e", "CommandInjection", 100),
    ("/bin/sh", "CommandInjection", 80),
    ("/bin/bash", "CommandInjection", 80),
    ("wget http", "CommandInjection", 70),
    ("curl http", "CommandInjection", 60),
    ("; ping ", "CommandInjection", 60),
];

/// 扫描器/攻击工具的 User-Agent 标识(小写子串)。
const SCANNER_UA: &[(&str, u32)] = &[
    ("sqlmap", 100),
    ("nikto", 100),
    ("nmap", 90),
    ("masscan", 90),
    ("acunetix", 100),
    ("nessus", 90),
    ("dirbuster", 80),
    ("gobuster", 70),
    ("wpscan", 80),
    ("hydra", 80),
    ("nuclei", 80),
];

pub struct RuleEngine {
    literals: AhoCorasick,
    /// 与 literals 的 pattern id 一一对应的 (类别, 分数)
    literal_meta: Vec<(&'static str, u32)>,
    /// 结构化正则:(已编译正则, 类别, 分数)
    regexes: Vec<(Regex, &'static str, u32)>,
}

impl RuleEngine {
    pub fn new() -> Self {
        let patterns: Vec<&str> = LITERAL_RULES.iter().map(|(p, _, _)| *p).collect();
        let literal_meta: Vec<(&'static str, u32)> =
            LITERAL_RULES.iter().map(|(_, c, s)| (*c, *s)).collect();

        let literals = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("字面量规则集构建失败");

        // 需要上下文的结构化特征(大小写不敏感用 (?i))
        let regex_defs: &[(&str, &str, u32)] = &[
            (r"(?i)\bunion\b\s+\bselect\b", "SQLi", 100),
            (r"(?i)\bor\b\s+\d+\s*=\s*\d+", "SQLi", 90),
            (r"(?i)<\s*script", "XSS", 90),
            (r"(?i)\bon\w+\s*=", "XSS", 60),
            (r"(?:%2e%2e|\.\.)[/\\]", "PathTraversal", 50),
        ];
        let regexes = regex_defs
            .iter()
            .map(|(re, c, s)| (Regex::new(re).expect("正则编译失败"), *c, *s))
            .collect();

        Self {
            literals,
            literal_meta,
            regexes,
        }
    }

    /// 对请求做检测,返回聚合结果。
    pub fn inspect(&self, req: &RequestSummary) -> Detection {
        let mut det = Detection::default();

        // 组合待检字符串:原始 + URL 解码。两者都扫,兼顾明文与百分号编码 payload。
        let raw = format!("{} {} {}", req.path, req.query, req.body);
        let decoded = percent_decode_lossy(&raw);
        let haystacks = [raw.as_str(), decoded.as_str()];

        // 用类别去重命中:同一 (类别, 模式) 只记一次,避免"原始+解码"重复计分。
        let mut seen: Vec<(String, String)> = Vec::new();

        for hay in haystacks {
            // 字面量匹配(重叠:相邻攻击特征可能共享字符,如 "../" 与 "/etc/passwd"
            // 共享斜杠;非重叠匹配会漏掉后者)
            for m in self.literals.find_overlapping_iter(hay) {
                let (category, score) = self.literal_meta[m.pattern().as_usize()];
                let pattern = LITERAL_RULES[m.pattern().as_usize()].0.to_string();
                record(&mut det, &mut seen, category, pattern, score);
            }
            // 结构化正则匹配
            for (re, category, score) in &self.regexes {
                if let Some(mat) = re.find(hay) {
                    record(
                        &mut det,
                        &mut seen,
                        category,
                        mat.as_str().to_string(),
                        *score,
                    );
                }
            }
        }

        // 扫描器 UA
        let ua = req.user_agent.to_ascii_lowercase();
        for (needle, score) in SCANNER_UA {
            if ua.contains(needle) {
                record(
                    &mut det,
                    &mut seen,
                    "Scanner",
                    (*needle).to_string(),
                    *score,
                );
            }
        }

        det
    }
}

impl Default for RuleEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// 记录一次命中(去重后累加分数)。
fn record(
    det: &mut Detection,
    seen: &mut Vec<(String, String)>,
    category: &str,
    pattern: String,
    score: u32,
) {
    let key = (category.to_string(), pattern.clone());
    if seen.contains(&key) {
        return;
    }
    seen.push(key);
    det.score += score;
    det.hits.push(Hit {
        category: category.to_string(),
        pattern,
        score,
    });
}

/// 单遍百分号解码(`%XX` → 字节)并把 `+` 归一为空格(表单 urlencoded 语义)。
/// 非法序列原样保留。仅用于检测归一化,不要求严格 RFC。
fn percent_decode_lossy(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                out.push(h * 16 + l);
                i += 3;
                continue;
            }
        }
        // 查询串里 '+' 表示空格;归一后 "union+select" 才能命中 "union select"
        out.push(if bytes[i] == b'+' { b' ' } else { bytes[i] });
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn summary(path: &str, query: &str, body: &str, ua: &str) -> RequestSummary {
        RequestSummary {
            method: "GET".into(),
            path: path.into(),
            query: query.into(),
            user_agent: ua.into(),
            body: body.into(),
            client_ip: "127.0.0.1".into(),
        }
    }

    #[test]
    fn benign_request_scores_zero() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/products", "id=42&sort=price", "", "Mozilla/5.0"));
        assert_eq!(d.score, 0, "正常请求不应命中: {:?}", d.hits);
    }

    #[test]
    fn sqli_union_select_blocks() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/items", "q=1 UNION SELECT password FROM users", "", "curl/8"));
        assert!(d.score >= 100, "UNION SELECT 应达拦截线: {:?}", d.hits);
        assert_eq!(d.primary_threat().as_deref(), Some("SQLi"));
    }

    #[test]
    fn classic_sqli_or_1_equals_1() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/login", "id=1' OR '1'='1", "", ""));
        assert!(d.score >= 100, "经典布尔注入应达拦截线: {:?}", d.hits);
    }

    #[test]
    fn xss_script_tag_blocks() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/search", "q=<script>alert(1)</script>", "", ""));
        assert!(d.score >= 90, "script 标签应命中 XSS: {:?}", d.hits);
        assert_eq!(d.primary_threat().as_deref(), Some("XSS"));
    }

    #[test]
    fn path_traversal_encoded_is_decoded() {
        let e = RuleEngine::new();
        // %2e%2e%2f = "../";配合 /etc/passwd
        let d = e.inspect(&summary("/download", "file=%2e%2e%2f%2e%2e%2fetc/passwd", "", ""));
        assert!(d.score >= 90, "编码路径穿越应被解码后命中: {:?}", d.hits);
        assert_eq!(d.primary_threat().as_deref(), Some("PathTraversal"));
    }

    #[test]
    fn sqli_union_select_with_plus_encoding() {
        // 查询串里空格常编码为 '+';归一后应命中 "union select"
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/items", "q=1+UNION+SELECT+pass+FROM+users", "", ""));
        assert!(d.score >= 100, "+ 编码的 UNION SELECT 应达拦截线: {:?}", d.hits);
        assert_eq!(d.primary_threat().as_deref(), Some("SQLi"));
    }

    #[test]
    fn scanner_ua_detected() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/", "", "", "sqlmap/1.7"));
        assert!(d.score >= 100, "sqlmap UA 应命中: {:?}", d.hits);
        assert_eq!(d.primary_threat().as_deref(), Some("Scanner"));
    }

    #[test]
    fn command_injection_detected() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/ping", "host=127.0.0.1; cat /etc/passwd", "", ""));
        assert!(d.score >= 80, "命令注入应命中: {:?}", d.hits);
    }
}
