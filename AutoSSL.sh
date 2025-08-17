#!/usr/bin/env bash
set -euo pipefail

# ======================================================================
# ZeroSSL 域名/IP 证书一键脚本（改良版）
# - 支持 IP 与域名证书
# - 稳健获取验证信息（含轮询与兜底）
# - DEBUG 调试输出 ZeroSSL 原始 JSON
# - 自动 HTTP 文件验证（80 端口）
# - 自动下载并输出 fullchain.pem / certificate.crt / ca_bundle.crt / private.key
#
# 用法示例：
#   ACCESS_KEY="xxxxxxxx" MODE="ip"     TARGET="1.2.3.4"   DEBUG=1 ./AutoSSL.sh
#   ACCESS_KEY="xxxxxxxx" MODE="domain" TARGET="example.com" DEBUG=1 ./AutoSSL.sh
#
# 可选变量：
#   EMAIL="me@example.com"     # 联系邮箱（可空）
#   BITS=2048                  # 私钥位数（默认2048）
#   OUT_DIR="/etc/zerossl-auto" # 基础输出目录（默认）
#   WEBROOT="/var/www/html"    # 已有网站根目录（会在其下写入验证文件）
# ======================================================================

# -------- 基础工具/日志 --------
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "需要命令：$1"; exit 1; }; }
log()      { echo "[$(date '+%F %T')] $*"; }
die()      { echo "[$(date '+%F %T')] ERROR: $*" >&2; exit 1; }
as_root()  { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

for c in curl jq openssl; do need_cmd "$c"; done
need_cmd python3

API="https://api.zerossl.com"
ACCESS_KEY="${ACCESS_KEY:-}"
MODE="${MODE:-}"              # ip | domain
TARGET="${TARGET:-}"          # 目标 IP 或域名
EMAIL="${EMAIL:-}"
BITS="${BITS:-2048}"
DEBUG="${DEBUG:-0}"
BASE_DIR="${OUT_DIR:-/etc/zerossl-auto}/${TARGET}"

STATE_DIR="${BASE_DIR}/state"
LIVE_DIR="${BASE_DIR}/live"
WORK_DIR="${BASE_DIR}/work"
WEB_TMP="${BASE_DIR}/webroot-tmp"

mkdir -p "$STATE_DIR" "$LIVE_DIR" "$WORK_DIR"

# -------- 辅助函数 --------
dump_if_debug() {
  if [[ "$DEBUG" = "1" ]]; then
    echo "----- DEBUG JSON BEGIN -----" 1>&2
    if command -v jq >/dev/null 2>&1; then
      echo "$1" | jq . 1>&2 || echo "$1" 1>&2
    else
      echo "$1" 1>&2
    fi
    echo "----- DEBUG JSON END -----" 1>&2
  fi
}

urlencode() {
  # 仅做最基本的 url-encode（足够编码 PEM/CSR）
  local LANG=C
  local length="${#1}"
  for (( i = 0; i < length; i++ )); do
    local c="${1:i:1}"
    case $c in
      [a-zA-Z0-9.~_-]) printf "%s" "$c" ;;
      *) printf '%%%02X' "'$c" ;;
    esac
  done
}

# -------- 1/7 生成私钥与 CSR（含 SAN）--------
gen_key_and_csr() {
  local CN="$TARGET"
  local KEY="$WORK_DIR/private.key"
  local CSR="$WORK_DIR/request.csr"
  local CFG="$WORK_DIR/openssl.cnf"

  if [[ ! -s "$KEY" ]]; then
    log "==> 1/7 生成私钥 ($BITS bits)"
    openssl genrsa -out "$KEY" "$BITS" >/dev/null 2>&1
  fi

  log "==> 1/7 生成 CSR (SAN=${MODE^^}:$TARGET)"
  cat >/tmp/openssl_base.cnf <<EOF
[ req ]
default_bits = ${BITS}
distinguished_name = req_distinguished_name
prompt = no
req_extensions = v3_req

[ req_distinguished_name ]
CN = ${CN}

[ v3_req ]
subjectAltName = @alt_names

[ alt_names ]
EOF

  if [[ "$MODE" == "ip" ]]; then
    echo "IP.1 = ${TARGET}" >> /tmp/openssl_base.cnf
  elif [[ "$MODE" == "domain" ]]; then
    echo "DNS.1 = ${TARGET}" >> /tmp/openssl_base.cnf
  else
    die "MODE 必须为 ip 或 domain"
  fi

  mv /tmp/openssl_base.cnf "$CFG"

  openssl req -new -key "$KEY" -out "$CSR" -config "$CFG" -extensions v3_req >/dev/null 2>&1

  echo "$KEY"
  echo "$CSR"
}

# -------- 2/7 创建证书订单 --------
create_order() {
  local CSR_FILE="$1"
  log "==> 2/7 创建证书订单 (ZeroSSL API)"
  local CSR_CONTENT
  CSR_CONTENT="$(cat "$CSR_FILE")"

  # 证书有效期（ZeroSSL 免费通常 90 天）
  local validity="90"

  # 提交参数：主要依赖 certificate_csr；certificate_domains 对域名，IP 也可直接用（ZeroSSL 会识别）
  # 如遇账号/计划限制，API 可能返回校验方式为空或报错。
  local resp
  resp="$(curl -fsS -X POST \
    --data-urlencode "certificate_csr=${CSR_CONTENT}" \
    --data "certificate_validity_days=${validity}" \
    --data "access_key=${ACCESS_KEY}" \
    --data "certificate_domains=${TARGET}" \
    ${EMAIL:+--data "certificate_contacts[]=${EMAIL}"} \
    "${API}/certificates")" || die "创建订单失败"

  dump_if_debug "$resp"
  local id
  id="$(echo "$resp" | jq -r '.id // empty')"
  [[ -n "$id" && "$id" != "null" ]] || die "未能从创建返回中获取证书ID"
  echo "$id"
}

# -------- 3/7 获取验证信息（稳健 + 轮询 + 兜底）--------
fetch_validation() {
  local CERT_ID="$1"
  log "==> 3/7 获取验证信息"

  local CERT_INFO=""
  # 最多轮询 3 次，防止刚创建后结构未就绪
  for _ in 1 2 3; do
    CERT_INFO="$(curl -fsS "${API}/certificates/${CERT_ID}?access_key=${ACCESS_KEY}")" || true
    [[ -n "$CERT_INFO" ]] && break
    sleep 2
  done

  dump_if_debug "$CERT_INFO"

  # 先按目标键取；取不到再退化为第一项
  local FILE_PATH FILE_CONTENT FILE_URL
  FILE_PATH="$(echo "$CERT_INFO" | jq -r ".validation.other_methods[\"$TARGET\"].file_validation_path // empty")"
  FILE_CONTENT="$(echo "$CERT_INFO" | jq -r ".validation.other_methods[\"$TARGET\"].file_validation_content // empty")"
  FILE_URL="$(echo "$CERT_INFO" | jq -r ".validation.other_methods[\"$TARGET\"].file_validation_url_http // empty")"

  if [[ -z "$FILE_PATH" || "$FILE_PATH" == "null" ]]; then
    FILE_PATH="$(echo "$CERT_INFO" | jq -r '.validation.other_methods | to_entries[0].value.file_validation_path // empty')"
    FILE_CONTENT="$(echo "$CERT_INFO" | jq -r '.validation.other_methods | to_entries[0].value.file_validation_content // empty')"
    FILE_URL="$(echo "$CERT_INFO" | jq -r '.validation.other_methods | to_entries[0].value.file_validation_url_http // empty')"
  fi

  [[ -n "$FILE_PATH" && "$FILE_PATH" != "null" ]] || die "未能获取验证文件路径（可能是套餐/配额限制，或 API 字段变更；请开 DEBUG=1 查看上方 CERT_INFO）"

  echo "$FILE_PATH" >"$STATE_DIR/file_path"
  echo "$FILE_CONTENT" >"$STATE_DIR/file_content"
  echo "$FILE_URL" >"$STATE_DIR/file_url"

  log "验证文件URL：${FILE_URL:-<unknown>}"
}

# -------- 4/7 准备验证文件（WEBROOT 或临时 80 端口）--------
prepare_http_challenge() {
  log "==> 4/7 准备验证文件"
  local PATH_REL CONTENT
  PATH_REL="$(cat "$STATE_DIR/file_path")"
  CONTENT="$(cat "$STATE_DIR/file_content")"

  if [[ "${WEBROOT:-}" != "" ]]; then
    # 写入到已有站点根目录
    local DEST="${WEBROOT%/}${PATH_REL}"
    mkdir -p "$(dirname "$DEST")"
    printf "%s" "$CONTENT" > "$DEST"
    echo "$DEST" > "$STATE_DIR/challenge_file"
    echo "webroot" > "$STATE_DIR/challenge_mode"
    log "已写入：$DEST"
  else
    # 起临时http服务（80端口）
    rm -rf "$WEB_TMP"; mkdir -p "$WEB_TMP${PATH_REL%/*}"
    printf "%s" "$CONTENT" > "$WEB_TMP${PATH_REL}"
    echo "$WEB_TMP${PATH_REL}" > "$STATE_DIR/challenge_file"
    echo "httpserver" > "$STATE_DIR/challenge_mode"

    # 尝试占用80端口
    log "启动临时 HTTP 服务 (python3 -m http.server 80)"
    # 后台起服务（工作目录切到 $WEB_TMP）
    ( cd "$WEB_TMP" && python3 -m http.server 80 >/dev/null 2>&1 ) &
    echo $! > "$STATE_DIR/http_pid"

    # 预留一点时间启动
    sleep 1
  fi
}

# -------- 5/7 触发验证 --------
trigger_validation() {
  local CERT_ID="$1"
  log "==> 5/7 触发验证 (ZeroSSL API)"

  local resp
  resp="$(curl -fsS -X POST "${API}/certificates/${CERT_ID}/challenges?access_key=${ACCESS_KEY}")" || die "触发验证失败"
  dump_if_debug "$resp"

  # 简单校验，无致命错误字段即可
  local success
  success="$(echo "$resp" | jq -r '.success // empty')"
  if [[ "$success" == "false" ]]; then
    die "ZeroSSL 返回验证失败：$(echo "$resp" | jq -r '.error.type,.error.code,.error.message' | tr '\n' ' ')"
  fi
}

# -------- 6/7 轮询签发状态并下载证书 --------
poll_and_download() {
  local CERT_ID="$1"
  log "==> 6/7 轮询签发状态"

  # 最多等 90 秒
  for i in $(seq 1 30); do
    local info
    info="$(curl -fsS "${API}/certificates/${CERT_ID}?access_key=${ACCESS_KEY}")" || true
    dump_if_debug "$info"

    local status
    status="$(echo "$info" | jq -r '.status // empty')"

    if [[ "$status" == "issued" || "$status" == "active" ]]; then
      log "证书已签发，开始下载"
      break
    fi
    if [[ "$status" == "cancelled" || "$status" == "revoked" || "$status" == "expired" ]]; then
      die "证书状态异常：$status"
    fi
    sleep 3
  done

  mkdir -p "$LIVE_DIR"
  # 使用 return 接口直接拿到 PEM 文本
  local dl
  dl="$(curl -fsS "${API}/certificates/${CERT_ID}/download/return?access_key=${ACCESS_KEY}")" || die "下载证书失败"
  dump_if_debug "$dl"

  # 预期字段：certificate.crt / ca_bundle.crt
  local CRT CA
  CRT="$(echo "$dl" | jq -r '.["certificate.crt"] // empty')"
  CA="$(echo "$dl" | jq -r '.["ca_bundle.crt"] // empty')"
  [[ -n "$CRT" ]] || die "未在下载返回中找到 certificate.crt"

  printf "%s\n" "$CRT" > "$LIVE_DIR/certificate.crt"
  [[ -n "$CA" ]] && printf "%s\n" "$CA" > "$LIVE_DIR/ca_bundle.crt" || true

  # 合并 fullchain
  if [[ -s "$LIVE_DIR/ca_bundle.crt" ]]; then
    cat "$LIVE_DIR/certificate.crt" "$LIVE_DIR/ca_bundle.crt" > "$LIVE_DIR/fullchain.pem"
  else
    cp "$LIVE_DIR/certificate.crt" "$LIVE_DIR/fullchain.pem"
  fi
  # 复制私钥
  cp "$WORK_DIR/private.key" "$LIVE_DIR/private.key"

  log "证书已保存："
  echo "  $LIVE_DIR/private.key"
  echo "  $LIVE_DIR/certificate.crt"
  [[ -s "$LIVE_DIR/ca_bundle.crt" ]] && echo "  $LIVE_DIR/ca_bundle.crt"
  echo "  $LIVE_DIR/fullchain.pem"
}

# -------- 7/7 清理临时资源 --------
cleanup_http() {
  log "==> 7/7 清理临时资源"
  if [[ -f "$STATE_DIR/http_pid" && "$(cat "$STATE_DIR/challenge_mode" 2>/dev/null || echo)" = "httpserver" ]]; then
    local pid; pid="$(cat "$STATE_DIR/http_pid" || true)"
    if [[ -n "${pid:-}" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  fi
}

issue_once() {
  as_root || die "请以 root 运行（需要占用 80 端口或写入 WEBROOT）"
  [[ -n "$ACCESS_KEY" ]] || die "ACCESS_KEY 不能为空"
  [[ "$MODE" = "ip" || "$MODE" = "domain" ]] || die "MODE 必须为 ip 或 domain"
  [[ -n "$TARGET" ]] || die "TARGET 不能为空"

  log "工作目录：$BASE_DIR"
  local KEY CSR CERT_ID

  readarray -t kc < <(gen_key_and_csr)
  KEY="${kc[0]}"; CSR="${kc[1]}"

  CERT_ID="$(create_order "$CSR")"
  echo "$CERT_ID" > "$STATE_DIR/cert_id"
  log "证书ID：$CERT_ID"

  fetch_validation "$CERT_ID"
  prepare_http_challenge
  trap cleanup_http EXIT

  trigger_validation "$CERT_ID"
  poll_and_download "$CERT_ID"

  log "完成。"
}

main() {
  if [[ -z "${MODE:-}" || -z "${TARGET:-}" || -z "${ACCESS_KEY:-}" ]]; then
    cat <<'USAGE'
用法：
  ACCESS_KEY="你的ZeroSSL密钥" MODE="ip|domain" TARGET="目标" [EMAIL="you@example.com"] [DEBUG=1] ./AutoSSL.sh

示例：
  ACCESS_KEY="xxxx" MODE="ip" TARGET="23.252.105.29" DEBUG=1 ./AutoSSL.sh
  ACCESS_KEY="xxxx" MODE="domain" TARGET="example.com" ./AutoSSL.sh

可选：
  WEBROOT="/var/www/html"   # 使用已有 80 端口站点根目录进行验证
  OUT_DIR="/etc/zerossl-auto"  # 输出目录根
USAGE
    exit 1
  fi
  issue_once
}

main "$@"
