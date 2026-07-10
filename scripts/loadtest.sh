#!/usr/bin/env bash
# ============================================================
# Limen WAF 端到端压测脚本
# 用法: chmod +x scripts/loadtest.sh && ./scripts/loadtest.sh
# 前提: cargo build --release 已完成
# 依赖: oha / hey / wrk 任一(可选,无则 fallback 到 curl 并发)
#       python3(启动假上游)
# ============================================================
set -euo pipefail

# --------------- 全局变量 ---------------
LIMPEN_BIN="./target/release/limen"
UPSTREAM_PORT=9911
PROXY_PORT=8091
TMP_CONFIG="/tmp/limen_loadtest_config.toml"
UPSTREAM_PID=""
LIMPEN_PID=""
LOAD_TESTER=""
LOAD_CMD=""

# --------------- 颜色 ---------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# --------------- 清理函数 ---------------
cleanup() {
  echo ""
  echo "--- 清理中 ---"
  if [ -n "$LIMPEN_PID" ] && kill -0 "$LIMPEN_PID" 2>/dev/null; then
    kill "$LIMPEN_PID" 2>/dev/null || true
    wait "$LIMPEN_PID" 2>/dev/null || true
    echo "[✔] 已关闭 Limen (PID $LIMPEN_PID)"
  fi
  if [ -n "$UPSTREAM_PID" ] && kill -0 "$UPSTREAM_PID" 2>/dev/null; then
    kill "$UPSTREAM_PID" 2>/dev/null || true
    wait "$UPSTREAM_PID" 2>/dev/null || true
    echo "[✔] 已关闭假上游 (PID $UPSTREAM_PID)"
  fi
  if [ -f "$TMP_CONFIG" ]; then
    rm -f "$TMP_CONFIG"
    echo "[✔] 已删除临时配置 $TMP_CONFIG"
  fi
}
trap cleanup EXIT INT TERM

# --------------- 前置检查 ---------------
echo "--- 前置检查 ---"

if [ ! -f "$LIMPEN_BIN" ]; then
  echo -e "${RED}[✘] 未找到 $LIMPEN_BIN,请先执行: cargo build --release${NC}"
  exit 1
fi
echo "[✔] $LIMPEN_BIN 存在"

if ! command -v python3 &>/dev/null; then
  echo -e "${RED}[✘] 未找到 python3,请安装 Python 3${NC}"
  exit 1
fi
echo "[✔] python3 可用"

# 探测负载生成器(按优先级: oha > hey > wrk > curl fallback)
if command -v oha &>/dev/null; then
  LOAD_TESTER="oha"
elif command -v hey &>/dev/null; then
  LOAD_TESTER="hey"
elif command -v wrk &>/dev/null; then
  LOAD_TESTER="wrk"
else
  LOAD_TESTER="curl_fallback"
fi

if [ "$LOAD_TESTER" = "curl_fallback" ]; then
  echo -e "${YELLOW}[!] 未安装 oha/hey/wrk,将使用 curl 并发 fallback(结果较粗略)${NC}"
  echo -e "${YELLOW}    建议: brew install oha${NC}"
else
  echo "[✔] 负载生成器: $LOAD_TESTER"
fi

# --------------- 启动假上游 ---------------
echo ""
echo "--- 启动假上游 (127.0.0.1:$UPSTREAM_PORT) ---"

python3 -c '
import http.server, socketserver

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")
    def log_message(self, *a):
        pass

socketserver.ThreadingTCPServer.allow_reuse_address = True
s = socketserver.ThreadingTCPServer(("127.0.0.1", 9911), H)
s.serve_forever()
' &
UPSTREAM_PID=$!
echo "[✔] 假上游已启动 (PID $UPSTREAM_PID)"

# --------------- 生成临时配置 ---------------
echo ""
echo "--- 生成临时配置 ---"

cat > "$TMP_CONFIG" <<'CONFEOF'
headless = true
listen = "127.0.0.1:8091"
upstream = "http://127.0.0.1:9911"
log_file = "/tmp/limen_loadtest.log"
db_path = ""

[detection]
block_threshold = 100
suspicious_threshold = 40
ngram_model = ""
ngram_threshold = 0.9
upstream_timeout_secs = 30

[llm]
enabled = false
provider = "openai_compat"
model = "unused"
base_url = "http://127.0.0.1:1"
api_key_env = "UNUSED"
timeout_ms = 1000
fail_mode = "fail_open"
CONFEOF

echo "[✔] 临时配置已写入 $TMP_CONFIG"
echo "    内容概要: headless=true, listen=:$PROXY_PORT, upstream=:$UPSTREAM_PORT, LLM 关闭"

# --------------- 启动 Limen ---------------
echo ""
echo "--- 启动 Limen ---"

"$LIMPEN_BIN" "$TMP_CONFIG" &
LIMPEN_PID=$!
echo "[✔] Limen 已启动 (PID $LIMPEN_PID),等待就绪..."
sleep 2

# 检查进程是否还活着
if ! kill -0 "$LIMPEN_PID" 2>/dev/null; then
  echo -e "${RED}[✘] Limen 启动后退出,请查看 $LIMPEN_BIN 是否正常${NC}"
  exit 1
fi
echo "[✔] Limen 运行中"

# --------------- 工具函数 ---------------
# 运行压测并返回核心指标
run_wrk() {
  local label="$1"; shift
  local url="$1"; shift
  echo ""
  echo "========================================"
  echo "  压测: $label"
  echo "  URL: $url"
  echo "========================================"
  echo ""

  # wrk 不支持指定时长(只有持续跑),这里用 -d 控制时长
  local output
  output=$(wrk -c 50 -d 10s "$url" 2>&1) || true
  echo "$output"

  # 提取 req/s(近似)
  local reqs
  reqs=$(echo "$output" | grep -oE 'Requests/sec:\s*[0-9.]+' | grep -oE '[0-9.]+' || echo "N/A")
  echo "$reqs"
}

run_hey() {
  local label="$1"; shift
  local url="$1"; shift
  echo ""
  echo "========================================"
  echo "  压测: $label"
  echo "  URL: $url"
  echo "========================================"
  echo ""

  local output
  output=$(hey -z 10s -c 50 "$url" 2>&1) || true
  echo "$output"

  local reqs
  reqs=$(echo "$output" | grep -oE 'Requests/sec:\s*[0-9.]+' | grep -oE '[0-9.]+' || echo "N/A")
  echo "$reqs"
}

run_oha() {
  local label="$1"; shift
  local url="$1"; shift
  echo ""
  echo "========================================"
  echo "  压测: $label"
  echo "  URL: $url"
  echo "========================================"
  echo ""

  local output
  output=$(oha -z 10s -c 50 --no-tui "$url" 2>&1) || true
  echo "$output"

  local reqs
  reqs=$(echo "$output" | grep -oE 'Requests/sec:\s*[0-9.]+' | grep -oE '[0-9.]+' || echo "N/A")
  echo "$reqs"
}

# curl 并发 fallback: 后台并发 50 个 curl 循环,统计 10s 内总请求数
run_curl_fallback() {
  local label="$1"; shift
  local url="$1"; shift
  echo ""
  echo "========================================"
  echo "  压测: $label"
  echo "  URL: $url"
  echo "  (curl 并发 fallback,精度有限)"
  echo "========================================"
  echo ""

  local counter_file
  counter_file=$(mktemp /tmp/limen_curl_counter.XXXXXX)

  # 启动 50 个后台 curl 子进程,每个循环发请求
  for _ in $(seq 1 50); do
    (
      end_time=$((SECONDS + 10))
      while [ "$SECONDS" -lt "$end_time" ]; do
        if curl -s -o /dev/null -w '' --max-time 5 "$url" 2>/dev/null; then
          # 原子计数:写入换行,最后 wc -l 统计
          echo "" >> "$counter_file"
        fi
      done
    ) &
  done

  echo "    压测中,请等待 10 秒..."
  sleep 10

  # 等后台进程退完
  wait 2>/dev/null || true

  local total
  total=$(wc -l < "$counter_file" 2>/dev/null || echo 0)
  total=$(echo "$total" | tr -d '[:space:]')
  rm -f "$counter_file"

  # 计算 req/s
  if [ -n "$total" ] && [ "$total" -gt 0 ]; then
    # 用 bc 或 awk 算除法
    local rps
    if command -v bc &>/dev/null; then
      rps=$(echo "scale=1; $total / 10" | bc)
    else
      rps=$(awk "BEGIN {printf \"%.1f\", $total / 10}")
    fi
    echo ""
    echo "  总请求数: $total"
    echo "  近似吞吐: ${rps} req/s"
    echo "$rps"
  else
    echo ""
    echo "  总请求数: 0(可能连接失败,请检查 Limen 是否正常监听)"
    echo "N/A"
  fi
}

# 统一调度:根据 LOAD_TESTER 选对应执行函数,返回 req/s 字符串
do_bench() {
  local label="$1"; shift
  local url="$1"; shift
  case "$LOAD_TESTER" in
    oha)   run_oha "$label" "$url" ;;
    hey)   run_hey "$label" "$url" ;;
    wrk)   run_wrk "$label" "$url" ;;
    *)     run_curl_fallback "$label" "$url" ;;
  esac
}

# --------------- 压测 ---------------
NORMAL_URL="http://127.0.0.1:$PROXY_PORT/api/test"
ATTACK_URL="http://127.0.0.1:$PROXY_PORT/api/test?q=1%20union%20select%20pass%20from%20users"

# 先快速探活:确认代理可达
echo ""
echo "--- 探活 ---"
if curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$NORMAL_URL" > /tmp/limen_probe.txt 2>/dev/null; then
  HTTP_CODE=$(cat /tmp/limen_probe.txt)
  echo "[✔] 代理可达,HTTP $HTTP_CODE ($NORMAL_URL)"
else
  echo -e "${RED}[✘] 无法连接代理 $NORMAL_URL,请检查 Limen 是否正常监听${NC}"
  exit 1
fi

# 攻击探活:应该返回 403
echo "--- 攻击探活 ---"
ATTACK_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 3 "$ATTACK_URL" 2>/dev/null || echo "000")
if [ "$ATTACK_CODE" = "403" ]; then
  echo -e "[✔] 攻击 URL 返回 403,规则生效"
else
  echo -e "${YELLOW}[!] 攻击 URL 返回 $ATTACK_CODE(期望 403),检查规则是否加载${NC}"
fi

# 跑两组压测
NORMAL_REQS=$(do_bench "A) 正常流量" "$NORMAL_URL" | tail -1)
ATTACK_REQS=$(do_bench "B) 攻击流量(SQL 注入)" "$ATTACK_URL" | tail -1)

# --------------- 总结 ---------------
echo ""
echo "========================================"
echo "  总结"
echo "========================================"
echo "  正常流量: ${NORMAL_REQS} req/s"
echo "  攻击流量: ${ATTACK_REQS} req/s"
echo ""
echo "  这是 Limen 反代+检测的端到端吞吐,数字取决于本机。"
echo "  如果期待更高吞吐,可尝试:"
echo "    - cargo build --release(已经是了)"
echo "    - 关闭 [detection] 中的 ngram_model"
echo "    - 减少规则或调高 block_threshold"
echo "========================================"
