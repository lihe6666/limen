//! 字符 n-gram 分类器:HashingVectorizer + 逻辑回归,与 Python 训练端逐位一致。
//! 模型布局(全小端):magic u32=0x4E47524D, D u32, nmin u32, nmax u32, bias f32, D 个 f32。

use std::collections::HashMap;

const MAGIC: u32 = 0x4E47524D;

pub struct NgramClassifier {
    w: Vec<f32>,
    b: f32,
    d: usize,
    nmin: usize,
    nmax: usize,
}

impl NgramClassifier {
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> anyhow::Result<Self> {
        let data = std::fs::read(path)?;
        anyhow::ensure!(data.len() >= 20, "模型文件过小");

        let magic = u32::from_le_bytes(data[0..4].try_into().unwrap());
        anyhow::ensure!(magic == MAGIC, "模型 magic 不匹配: 期望 0x{MAGIC:08X}, 实际 0x{magic:08X}");

        let d = u32::from_le_bytes(data[4..8].try_into().unwrap()) as usize;
        let nmin = u32::from_le_bytes(data[8..12].try_into().unwrap()) as usize;
        let nmax = u32::from_le_bytes(data[12..16].try_into().unwrap()) as usize;
        let b = f32::from_le_bytes(data[16..20].try_into().unwrap());

        let expected_len = 20 + d * 4;
        anyhow::ensure!(data.len() >= expected_len, "模型权重数据不足: 期望 {expected_len} 字节, 实际 {} 字节", data.len());

        let mut w = Vec::with_capacity(d);
        for i in 0..d {
            let start = 20 + i * 4;
            w.push(f32::from_le_bytes(data[start..start + 4].try_into().unwrap()));
        }

        Ok(Self { w, b, d, nmin, nmax })
    }

    pub fn score_parts(&self, method: &str, path: &str, query: &str, body: &str, headers: &str) -> f32 {
        let text = feature_text(method, path, query, body, headers);
        self.score_feature_text(&text)
    }

    pub fn score_feature_text(&self, text: &str) -> f32 {
        let feats = hash_features(text, self.d, self.nmin, self.nmax);
        let mut acc: f64 = self.b as f64;
        for (idx, v) in &feats {
            acc += self.w[*idx as usize] as f64 * v;
        }
        (1.0 / (1.0 + (-acc).exp())) as f32
    }
}

fn single_percent_decode(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut out = String::with_capacity(chars.len());
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '%' && i + 2 < chars.len() {
            let hex_str = format!("{}{}", chars[i + 1], chars[i + 2]);
            if let Ok(val) = u8::from_str_radix(&hex_str, 16) {
                out.push(val as char);
                i += 3;
                continue;
            }
        }
        out.push(if chars[i] == '+' { ' ' } else { chars[i] });
        i += 1;
    }
    out
}

/// 去掉请求头字符串里的 Host 行,理由:BlazeHTTP 黑样本几乎全部打同一靶机 Host,
/// 保留会让模型学到"Host=靶机 IP → 攻击"的数据集 artifact,而非真实 payload 信号。
/// 必须与 ml/ngram_clf.py::_strip_host_header 逐位镜像。
fn strip_host_header(headers: &str) -> String {
    headers
        .lines()
        .filter(|line| {
            let name = line.split_once(':').map(|(n, _)| n).unwrap_or(line);
            !name.trim().eq_ignore_ascii_case("host")
        })
        .collect::<Vec<_>>()
        .join("\n")
}

pub fn feature_text(method: &str, path: &str, query: &str, body: &str, headers: &str) -> String {
    let body_trunc: String = body.chars().take(4096).collect();
    let headers_filtered = strip_host_header(headers);
    let headers_trunc: String = headers_filtered.chars().take(4096).collect();
    let raw = format!("{method} {path} {query} {body_trunc} {headers_trunc}");
    let decoded = single_percent_decode(&raw);
    format!("{raw} {decoded}").to_lowercase()
}

fn hash_features(text: &str, d: usize, nmin: usize, nmax: usize) -> HashMap<u32, f64> {
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();
    let mut feats: HashMap<u32, f64> = HashMap::new();
    let mask = (d as u32).wrapping_sub(1);

    for n in nmin..=nmax {
        if n > len {
            continue;
        }
        for i in 0..=len - n {
            let ngram: String = chars[i..i + n].iter().collect();
            let hash = crc32fast::hash(ngram.as_bytes());
            let idx = hash & mask;
            *feats.entry(idx).or_insert(0.0) += 1.0;
        }
    }

    let sum_sq: f64 = feats.values().map(|v| v * v).sum();
    let norm = if sum_sq > 0.0 { sum_sq.sqrt() } else { 1.0 };
    for v in feats.values_mut() {
        *v /= norm;
    }

    feats
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parity_with_python() {
        let parity_path = "ml/parity.json";
        let model_path = "ml/model.bin";

        let parity_data = match std::fs::read_to_string(parity_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("parity 测试跳过: 无法读取 {parity_path}: {e}");
                return;
            }
        };

        let classifier = match NgramClassifier::load(model_path) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("parity 测试跳过: 无法加载 {model_path}: {e}");
                return;
            }
        };

        #[derive(serde::Deserialize)]
        struct Case {
            method: String,
            path: String,
            query: String,
            body: String,
            #[serde(default)]
            headers: String,
            feature_text: String,
            score: f64,
        }

        let cases: Vec<Case> = match serde_json::from_str(&parity_data) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("parity 测试跳过: 无法解析 {parity_path}: {e}");
                return;
            }
        };

        for (i, case) in cases.iter().enumerate() {
            let ft = feature_text(&case.method, &case.path, &case.query, &case.body, &case.headers);
            assert_eq!(
                ft, case.feature_text,
                "parity 用例 {i}: feature_text 不一致\n  期望: {:?}\n  实际: {:?}",
                case.feature_text, ft
            );

            let score = classifier.score_parts(&case.method, &case.path, &case.query, &case.body, &case.headers);
            let diff = (score as f64 - case.score).abs();
            assert!(
                diff < 1e-4,
                "parity 用例 {i}: score 偏差过大 (diff={diff:.2e})\n  期望: {:.10}\n  实际: {:.10}",
                case.score, score
            );
        }

        eprintln!("parity 测试通过: {} 条全部一致", cases.len());
    }
}
