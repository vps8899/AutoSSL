#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZeroSSL 域名/IP 证书一键脚本（签发 + 自动续签, 中文交互）
# 增强：
#  - 全局日志输出到 $LOG_FILE（默认 /var/log/zerossl_oneclick.log）
#  - 关键 API 返回体快照保存到 $STATE_DIR/last_*.json 方便排障
#  - DEBUG=1 开启命令追踪（set -x）
#  - 其他逻辑与原版保持一致
# ============================================================================

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "需要命令：$1"; exit 1; }; }
log()      { echo "[$(date '+%F %T')] $*"; }
die()      { echo "[$(date '+%F %T')] ERROR: $*" >&2; exit 1; }
as_root()  { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

for c in curl jq openssl unzip awk; do need_cmd "$c"; done
if [[ -z "${WEBROOT:-}" ]]; then
  need_cmd python3 || die "未检测到 python3，且未提供 WEBROOT；无法临时起 80 端口验证服务"
fi

# ---- 日志设置 ----
LOG_FILE="${LOG_FILE:-/var/log/zerossl_oneclick.log}"
mkdir -p "$(dirname "$LOG_FILE")" || true
: >"$LOG_FILE" || true
chmod 600 "$LOG_FILE" 2>/dev/null || true
# 将 stdout/stderr 同步写入控制台与日志文件，并加时间戳
exec > >(awk '{ print strftime("[%Y-%m-%d %H:%M:%S]"), $0 }' | tee -a "$LOG_FILE") 2>&1

# DEBUG=1 时打开命令追踪
[[ "${DEBUG:-0}" == "1" ]] && set -x

ACCESS_KEY="${ACCESS_KEY:-}"
MODE="${MODE:-}"              # domain / ip
TARGET="${TARGET:-}"          # 域名 / IP(IPv4/IPv6)
VALID_DAYS="${VALID_DAYS:-90}"
WEBROOT="${WEBROOT:-}"
KEY_TYPE="${KEY_TYPE:-rsa:2048}"
DEBUG="${DEBUG:-0}"

TMP_TARGET="${TARGET:-placeholder}"

if as_root; then
  DEFAULT_BASE="/etc/zerossl-ip"
else
  DEFAULT_BASE="$HOME/.zerossl-ip"
fi

CONFIG_DIR="${CONFIG_DIR:-$DEFAULT_BASE/$TMP_TARGET}"
STATE_DIR="${STATE_DIR:-$CONFIG_DIR/state}"
ENV_FILE="$STATE_DIR/.env"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

debug() { [[ "$DEBUG" == "1" ]] && log "[DEBUG] $*"; }

WORKDIR=""
SERVER_PID=""
cleanup() {
  if [[ -n "${SERVER_PID:-}" ]] && kill -0 "$SERVER_PID" 2>/dev/null; then
    kill "$SERVER_PID" 2>/dev/null || true
  fi
  [[ -n "${WORKDIR:-}" ]] && rm -rf "$WORKDIR" || true
}
trap cleanup EXIT

select_mode_and_target() {
  if [[ -n "${MODE:-}" && -n "${TARGET:-}" ]]; then return 0; fi
  echo "================ 证书类型选择 ================"
  echo "1) 域名证书   (例如：www.example.com)"
  echo "2) IP 证书    (例如：203.0.113.10 或 2001:db8::1)"
  echo "============================================="
  read -rp "请输入数字选择 (1/2): " choice
  case "$choice" in
    1) MODE="domain"; read -rp "请输入域名（例如：www.example.com）: " TARGET ;;
    2) MODE="ip";     read -rp "请输入公网 IP（IPv4/IPv6 皆可）: " TARGET ;;
    *) die "无效选择" ;;
  esac
}

prompt_access_key_if_needed() {
  if [[ -z "${ACCESS_KEY:-}" ]]; then
    read -rsp "请输入 ZeroSSL API Access Key: " ACCESS_KEY
    echo
  fi
  [[ -n "$ACCESS_KEY" ]] || die "ACCESS_KEY 不能为空（请在 ZeroSSL 控制台获取）"
}

recompute_paths_by_target() {
  local safe_target
  safe_target="${TARGET//\//_}"
  local base="$DEFAULT_BASE"
  CONFIG_DIR="${CONFIG_DIR:-$base/$safe_target}"
  STATE_DIR="${STATE_DIR:-$CONFIG_DIR/state}"
  LIVE_DIR="${LIVE_DIR:-$CONFIG_DIR/live}"
  ENV_FILE="$STATE_DIR/.env"
  mkdir -p "$STATE_DIR" "$LIVE_DIR"
}

persist_env() {
  mkdir -p "$STATE_DIR"
  cat > "$ENV_FILE" <<EOF
ACCESS_KEY="$ACCESS_KEY"
MODE="$MODE"
TARGET="$TARGET"
VALID_DAYS="$VALID_DAYS"
WEBROOT="$WEBROOT"
LIVE_DIR="$LIVE_DIR"
CONFIG_DIR="$CONFIG_DIR"
STATE_DIR="$STATE_DIR"
KEY_TYPE="$KEY_TYPE"
DEBUG="$DEBUG"
LOG_FILE="$LOG_FILE"
EOF
  chmod 600 "$ENV_FILE" || true
}

gen_key_and_csr() {
  local kt="$1"
  case "$kt" in
    rsa:* )
      local bits="${kt#rsa:}"; [[ -n "$bits" ]] || bits="2048"
      openssl req -new -newkey "rsa:${bits}" -nodes \
        -keyout server.key -out server.csr \
        -config openssl_san.cnf
      ;;
    ec:* )
      local curve="${kt#ec:}"; [[ -n "$curve" ]] || curve="prime256v1"
      openssl ecparam -name "$curve" -genkey -noout -out server.key
      openssl req -new -key server.key -out server.csr -config openssl_san.cnf
      ;;
    * ) die "不支持的 KEY_TYPE：$kt（示例：rsa:2048 或 ec:prime256v1）" ;;
  esac
  debug "使用 KEY_TYPE=$kt"
}

issue_once() {
  WORKDIR="$(mktemp -d -t zerossl_${MODE}_${TARGET//\//_}_XXXX)"
  cd "$WORKDIR"

  log "==> 1/7 生成私钥与 CSR (SAN=${MODE^^}:$TARGET)"
  cat > openssl_san.cnf <<EOF
[ req ]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[ dn ]
CN = ${TARGET}

[ v3_req ]
$( if [[ "$MODE" == "ip" ]]; then echo "subjectAltName = IP:${TARGET}"; else echo "subjectAltName = DNS:${TARGET}"; fi )
EOF

  umask 077
  gen_key_and_csr "$KEY_TYPE"

  log "==> 2/7 创建证书订单 (ZeroSSL API)"
  CREATE_JSON="$(curl -fsS -X POST "https://api.zerossl.com/certificates?access_key=${ACCESS_KEY}" \
    --data-urlencode "certificate_csr@server.csr" \
    --data "certificate_domains=${TARGET}&certificate_validity_days=${VALID_DAYS}&strict_domains=1" || true)"
  echo "$CREATE_JSON" > "$STATE_DIR/last_create.json"

  CERT_ID="$(echo "$CREATE_JSON" | jq -r '.id // .certificate.id // empty')"
  if [[ -z "${CERT_ID:-}" || "$CERT_ID" == "null" ]]; then
    jq . "$STATE_DIR/last_create.json" 2>/dev/null || true
    die "创建证书失败（可能是配额、套餐限制或 CSR/CN 不匹配）。"
  fi
  log "证书ID：$CERT_ID"

  log "==> 3/7 获取 HTTP 文件验证信息"
  CERT_INFO="$(curl -fsS "https://api.zerossl.com/certificates/${CERT_ID}?access_key=${ACCESS_KEY}" || true)"
  echo "$CERT_INFO" > "$STATE_DIR/last_certinfo.json"

  VALID_NODE="$(echo "$CERT_INFO" | jq -r --arg t "$TARGET" '.validation.other_methods[$t] // .validation.other_methods[0] // empty')"
  if [[ -z "$VALID_NODE" || "$VALID_NODE" == "null" ]]; then
    jq . "$STATE_DIR/last_certinfo.json" 2>/dev/null || true
    die "未找到验证信息（请确认 80 端口对外开放，且 $TARGET 已解析到本机）。"
  fi
  FILE_PATH="$(echo "$VALID_NODE" | jq -r '.file_validation_path')"
  FILE_CONTENT="$(echo "$VALID_NODE" | jq -r '.file_validation_content')"
  FILE_URL="$(echo "$VALID_NODE" | jq -r '.file_validation_url_http')"

  log "验证文件URL：$FILE_URL"
  log "验证文件相对路径：$FILE_PATH"
  echo "$FILE_PATH"    > "$STATE_DIR/last_validation_path.txt"
  echo "$FILE_CONTENT" > "$STATE_DIR/last_validation_content.txt"

  log "==> 4/7 准备验证文件到 Web 根目录"
  if [[ -n "${WEBROOT:-}" ]]; then
    mkdir -p "${WEBROOT}$(dirname "$FILE_PATH")"
    printf "%s" "$FILE_CONTENT" > "${WEBROOT}${FILE_PATH}"
    log "已写入 ${WEBROOT}${FILE_PATH}，请确保 80 端口公网可达。"
  else
    WEBROOT="${WORKDIR}/webroot"
    mkdir -p "${WEBROOT}$(dirname "$FILE_PATH")"
    printf "%s" "$FILE_CONTENT" > "${WEBROOT}${FILE_PATH}"
    log "未设置 WEBROOT，启动临时 http.server（监听 80，绑定 0.0.0.0）..."
    if as_root; then
      nohup python3 -m http.server 80 --bind 0.0.0.0 --directory "$WEBROOT" >/dev/null 2>&1 &
      SERVER_PID=$!
      log "已启动临时服务 PID=$SERVER_PID"
    else
      die "需要 root 权限以监听 80 端口，或设置 WEBROOT 指向现有站点"
    fi
  fi

  log "==> 5/7 触发验证并轮询状态"
  curl -fsS -X POST "https://api.zerossl.com/certificates/${CERT_ID}/challenges?access_key=${ACCESS_KEY}" \
    --data "validation_method=HTTP_CSR_HASH" >/dev/null || true

  STATUS=""
  for _ in $(seq 1 36); do
    STATUS_JSON="$(curl -fsS "https://api.zerossl.com/certificates/${CERT_ID}/status?access_key=${ACCESS_KEY}" || true)"
    if [[ -z "$STATUS_JSON" || "$STATUS_JSON" == "Not Found" ]]; then
      STATUS_JSON="$(curl -fsS "https://api.zerossl.com/verification/status?access_key=${ACCESS_KEY}&certificate_id=${CERT_ID}" || true)"
    fi
    echo "$STATUS_JSON" > "$STATE_DIR/last_status.json"
    STATUS="$(echo "$STATUS_JSON" | jq -r '.status // .validation_status // empty')"
    [[ -z "$STATUS" || "$STATUS" == "null" ]] && STATUS="$(curl -fsS "https://api.zerossl.com/certificates/${CERT_ID}?access_key=${ACCESS_KEY}" | jq -r '.status')"
    log "当前状态：${STATUS:-unknown}"
    [[ "$STATUS" == "issued" ]] && break
    sleep 5
  done
  [[ "$STATUS" == "issued" ]] || die "验证未完成或失败（请检查 80 端口、防火墙、站点解析）：$FILE_URL"

  log "==> 6/7 下载并整理证书"
  mkdir -p cert
  curl -fsS -L "https://api.zerossl.com/certificates/${CERT_ID}/download?access_key=${ACCESS_KEY}" -o cert.zip
  unzip -o cert.zip -d cert >/dev/null

  CERT_CRT="cert/certificate.crt"
  CA_BUNDLE="cert/ca_bundle.crt"
  PRIV_KEY="server.key"
  FULLCHAIN="cert/fullchain.pem"
  cat "$CERT_CRT" "$CA_BUNDLE" > "$FULLCHAIN"

  install -d "$LIVE_DIR"
  install -m 600 "$PRIV_KEY"   "$LIVE_DIR/privkey.key"
  install -m 644 "$CERT_CRT"   "$LIVE_DIR/cert.crt"
  install -m 644 "$CA_BUNDLE"  "$LIVE_DIR/ca_bundle.crt"
  install -m 644 "$FULLCHAIN"  "$LIVE_DIR/fullchain.pem"

  log "==> 7/7 完成并输出证书路径"
  echo
  echo "证书路径:"
  echo "  Server Certificate:        $LIVE_DIR/cert.crt"
  echo "  Private Key:               $LIVE_DIR/privkey.key"
  echo "  CA Bundle:                 $LIVE_DIR/ca_bundle.crt"
  echo "  Full Chain:                $LIVE_DIR/fullchain.pem"
  echo "  Log File:                  $LOG_FILE"
  echo
  echo "Nginx 示例:"
  echo "  ssl_certificate     $LIVE_DIR/fullchain.pem;"
  echo "  ssl_certificate_key $LIVE_DIR/privkey.key;"
  echo
}

abs_self() {
  local p="$0"
  if command -v readlink >/dev/null 2>&1; then
    readlink -f "$p" 2>/dev/null || perl -MCwd -e 'print Cwd::abs_path(shift),"\n"' "$p"
  else
    perl -MCwd -e 'print Cwd::abs_path(shift),"\n"' "$p"
  fi
}

install_systemd() {
  as_root || return 1
  local script_path; script_path="$(abs_self)"
  [[ -n "$script_path" ]] || die "无法解析脚本绝对路径"

  local svc="/etc/systemd/system/zerossl-${MODE}-${TARGET//\//_}.service"
  local tim="/etc/systemd/system/zerossl-${MODE}-${TARGET//\//_}.timer"

  cat > "$svc" <<EOF
[Unit]
Description=ZeroSSL ${MODE} cert renew for ${TARGET}
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=${ENV_FILE}
ExecStart=${script_path} --renew
WorkingDirectory=/
User=root
EOF

  cat > "$tim" <<EOF
[Unit]
Description=Run ZeroSSL ${MODE} cert renew for ${TARGET} every 30 days

[Timer]
OnBootSec=5min
OnUnitActiveSec=30d
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$(basename "$tim")" || true
  log "已安装 systemd 定时器：$(basename "$tim")（每30天尝试续签）"
}

install_cron() {
  local script_path; script_path="$(abs_self)"
  [[ -n "$script_path" ]] || die "无法解析脚本绝对路径"
  local line="17 3 1 * * ACCESS_KEY=$(printf %q "$ACCESS_KEY") MODE=$(printf %q "$MODE") TARGET=$(printf %q "$TARGET") VALID_DAYS=$(printf %q "$VALID_DAYS") WEBROOT=$(printf %q "$WEBROOT") LIVE_DIR=$(printf %q "$LIVE_DIR") STATE_DIR=$(printf %q "$STATE_DIR") CONFIG_DIR=$(printf %q "$CONFIG_DIR") KEY_TYPE=$(printf %q "$KEY_TYPE") DEBUG=$(printf %q "$DEBUG") LOG_FILE=$(printf %q "$LOG_FILE") /usr/bin/env bash $script_path --renew >> $LOG_FILE 2>&1"
  (crontab -l 2>/dev/null || true; echo "$line") | crontab -
  log "已安装 cron 定时任务：每月 1 日 03:17 尝试续签（日志见 $LOG_FILE）"
}

main() {
  if [[ "${1:-}" == "--renew" ]]; then
    [[ -f "$ENV_FILE" ]] || die "--renew 模式找不到 $ENV_FILE，请先运行一次完成初始化"
    recompute_paths_by_target
    issue_once
    if command -v nginx >/dev/null 2>&1; then
      nginx -t >/dev/null 2>&1 && (systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null) || true
    fi
    log "续签完成。"
    exit 0
  fi

  select_mode_and_target
  prompt_access_key_if_needed

  recompute_paths_by_target
  persist_env

  issue_once

  log "==> 正在安装自动续签..."
  if command -v systemctl >/dev/null 2>&1; then
    install_systemd || install_cron
  else
    install_cron
  fi
  log "自动续签安装完成。"

  if command -v nginx >/dev/null 2>&1; then
    nginx -t >/dev/null 2>&1 && (systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null) || true
  fi

  log "全部完成。"
}

main "$@"
