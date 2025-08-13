#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZeroSSL IP/域名 证书 一键脚本（签发 + 自动续签, 中文交互版）
# - 支持“域名证书”或“IP 证书”的交互式选择
# - 默认 90 天（ZeroSSL 免费证书常见期限），自动安装 systemd timer 或 cron 实现无人值守续签
# - 结束时打印中文+英文证书路径；续签后覆盖同路径，无需改 Web 配置
#
# 初次运行（交互）：
#   sudo bash ./zerossl_ip_oneclick_cn.sh
#
# 非交互（环境变量直传，便于脚本化/CI）：
#   sudo ACCESS_KEY="xxx" MODE="domain" TARGET="www.example.com" bash ./zerossl_ip_oneclick_cn.sh
#   sudo ACCESS_KEY="xxx" MODE="ip"     TARGET="203.0.113.10"    bash ./zerossl_ip_oneclick_cn.sh
#
# 可选环境变量：
#   WEBROOT=/var/www/html
#   LIVE_DIR=/etc/zerossl-ip/<target>/live
#   VALID_DAYS=90
#   STATE_DIR=...（存放.env）
#
# 续签模式：由定时器/cron 调用，等价于：
#   sudo bash ./zerossl_ip_oneclick_cn.sh --renew
# ============================================================================

# ------------- 工具与通用函数 -------------
need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "需要命令：$1"; exit 1; }; }
log() { printf "%s\n" "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }
as_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

for c in curl jq openssl unzip; do need_cmd "$c"; done
# 若未设置 WEBROOT，将使用临时 http.server
if [[ -z "${WEBROOT:-}" ]]; then
  need_cmd python3 || die "未检测到 python3，且未提供 WEBROOT；无法临时起 80 端口验证服务"
fi

# ------------- 从环境或 .env 读取配置（便于 --renew） -------------
ACCESS_KEY="${ACCESS_KEY:-}"
MODE="${MODE:-}"        # "domain" 或 "ip"
TARGET="${TARGET:-}"    # 域名 或 IPv4
VALID_DAYS="${VALID_DAYS:-90}"
WEBROOT="${WEBROOT:-}"

# 先临时赋一个占位，以便构造路径；真正值在选择后重算
TMP_TARGET="${TARGET:-placeholder}"

if as_root; then
  DEFAULT_BASE="/etc/zerossl-ip"
else
  DEFAULT_BASE="$HOME/.zerossl-ip"
fi

CONFIG_DIR="${CONFIG_DIR:-$DEFAULT_BASE/$TMP_TARGET}"
STATE_DIR="${STATE_DIR:-$CONFIG_DIR/state}"
ENV_FILE="$STATE_DIR/.env"

# 如果存在历史 .env，先加载（用于 --renew 或首次已保存过的交互结果）
if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  source "$ENV_FILE"
fi

# 选择/确认 MODE 与 TARGET（交互）
select_mode_and_target() {
  if [[ -n "${MODE:-}" && -n "${TARGET:-}" ]]; then
    return 0
  fi
  echo "================ 证书类型选择 ================"
  echo "1) 域名证书   (例如：www.example.com)"
  echo "2) IP 证书    (例如：203.0.113.10)"
  echo "============================================="
  read -rp "请输入数字选择 (1/2): " choice
  case "$choice" in
    1)
      MODE="domain"
      read -rp "请输入域名（例如：www.example.com）: " TARGET
      ;;
    2)
      MODE="ip"
      read -rp "请输入公网 IPv4（例如：203.0.113.10）: " TARGET
      ;;
    *)
      die "无效选择"
      ;;
  esac
}

# 首次或非续签模式时，若 ACCESS_KEY 为空，交互输入（隐藏回显）
prompt_access_key_if_needed() {
  if [[ -z "${ACCESS_KEY:-}" ]]; then
    read -rsp "请输入 ZeroSSL API Access Key: " ACCESS_KEY
    echo
  fi
  [[ -n "$ACCESS_KEY" ]] || die "ACCESS_KEY 不能为空"
}

# 根据 MODE+TARGET 计算路径（LIVE_DIR, CONFIG_DIR, ENV_FILE 等）
recompute_paths_by_target() {
  # 以 TARGET 构造安全目录名（域名包含点，直接用也可；这里仅做最小替换）
  SAFE_TARGET="${TARGET//\//_}"
  if as_root; then
    BASE="$DEFAULT_BASE"
  else
    BASE="$DEFAULT_BASE"
  end_if_dummy=1
  CONFIG_DIR="${CONFIG_DIR:-$BASE/$SAFE_TARGET}"
  STATE_DIR="${STATE_DIR:-$CONFIG_DIR/state}"
  LIVE_DIR_DEFAULT="$CONFIG_DIR/live"
  LIVE_DIR="${LIVE_DIR:-$LIVE_DIR_DEFAULT}"
  ENV_FILE="$STATE_DIR/.env"
}

# 保存 .env，供续签使用
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
EOF
  chmod 600 "$ENV_FILE" || true
}

# ------------------- 主流程（签发一次） -------------------
issue_once() {
  local workdir
  workdir="$(mktemp -d -t zerossl_${MODE}_${TARGET//\//_}_XXXX)"
  trap 'rm -rf "$workdir" || true' EXIT
  cd "$workdir"

  log "==> 1/7 生成私钥与 CSR (SAN=${MODE^^}:${TARGET})"
  cat > openssl_san.cnf <<EOF
[ req ]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[ dn ]
CN = ${TARGET}

[ v3_req ]
$( [[ "$MODE" == "ip" ]] && echo "subjectAltName = IP:${TARGET}" || echo "subjectAltName = DNS:${TARGET}" )
EOF

  openssl req -new -newkey rsa:2048 -nodes \
    -keyout server.key -out server.csr \
    -config openssl_san.cnf

  log "==> 2/7 创建证书订单 (ZeroSSL API)"
  CREATE_JSON="$(curl -sS -X POST "https://api.zerossl.com/certificates?access_key=${ACCESS_KEY}" \
    --data-urlencode "certificate_csr@server.csr" \
    --data "certificate_domains=${TARGET}&certificate_validity_days=${VALID_DAYS}&strict_domains=1")" || true

  CERT_ID="$(echo "$CREATE_JSON" | jq -r '.id // .certificate.id // empty')"
  if [[ -z "$CERT_ID" || "$CERT_ID" == "null" ]]; then
    echo "$CREATE_JSON" | jq . || true
    die "创建证书失败（可能是配额、目标不可用等）。"
  fi
  log "证书ID：$CERT_ID"

  log "==> 3/7 获取 HTTP 文件验证信息"
  CERT_INFO="$(curl -sS "https://api.zerossl.com/certificates/${CERT_ID}?access_key=${ACCESS_KEY}")"
  VALID_NODE="$(echo "$CERT_INFO" | jq -r --arg t "$TARGET" '.validation.other_methods[$t]')"
  if [[ -z "$VALID_NODE" || "$VALID_NODE" == "null" ]]; then
    echo "$CERT_INFO" | jq . || true
    die "未找到验证信息（请确认 TARGET 是否已解析到本机公网IP，且 80 端口对外开放）"
  fi
  FILE_PATH="$(echo "$VALID_NODE" | jq -r '.file_validation_path')"
  FILE_CONTENT="$(echo "$VALID_NODE" | jq -r '.file_validation_content')"
  FILE_URL="$(echo "$VALID_NODE" | jq -r '.file_validation_url_http')"

  log "验证文件URL：$FILE_URL"
  log "验证文件相对路径：$FILE_PATH"

  log "==> 4/7 准备验证文件到 Web 根目录"
  SERVER_PID=""
  if [[ -n "${WEBROOT:-}" ]]; then
    mkdir -p "${WEBROOT}$(dirname "$FILE_PATH")"
    printf "%s" "$FILE_CONTENT" > "${WEBROOT}${FILE_PATH}"
    log "已写入 ${WEBROOT}${FILE_PATH}，请确保 80 端口公网可达。"
  else
    WEBROOT="${workdir}/webroot"
    mkdir -p "${WEBROOT}$(dirname "$FILE_PATH")"
    printf "%s" "$FILE_CONTENT" > "${WEBROOT}${FILE_PATH}"
    log "未设置 WEBROOT，启动临时 http.server（监听 80）..."
    if as_root; then
      nohup python3 -m http.server 80 --directory "$WEBROOT" >/dev/null 2>&1 &
      SERVER_PID=$!
      trap '[[ -n "${SERVER_PID:-}" ]] && kill $SERVER_PID || true' EXIT
    else
      die "需要 root 权限以监听 80 端口，或设置 WEBROOT 指向现有站点"
    fi
  fi

  log "==> 5/7 触发验证并轮询状态"
  TRIGGER="$(curl -sS -X POST "https://api.zerossl.com/certificates/${CERT_ID}/challenges?access_key=${ACCESS_KEY}" \
    --data "validation_method=HTTP_CSR_HASH")" || true

  STATUS=""
  for i in {1..36}; do
    STATUS_JSON="$(curl -sS "https://api.zerossl.com/certificates/${CERT_ID}/status?access_key=${ACCESS_KEY}" || true)"
    if [[ -z "$STATUS_JSON" || "$STATUS_JSON" == "Not Found" ]]; then
      STATUS_JSON="$(curl -sS "https://api.zerossl.com/verification/status?access_key=${ACCESS_KEY}&certificate_id=${CERT_ID}")"
    fi
    STATUS="$(echo "$STATUS_JSON" | jq -r '.status // .validation_status // empty')"
    [[ -z "$STATUS" || "$STATUS" == "null" ]] && STATUS="$(curl -sS "https://api.zerossl.com/certificates/${CERT_ID}?access_key=${ACCESS_KEY}" | jq -r '.status')"
    log "当前状态：${STATUS:-unknown}"
    if [[ "$STATUS" == "issued" ]]; then break; fi
    sleep 5
  done
  [[ "$STATUS" == "issued" ]] || die "验证未完成或失败（请检查 80 端口、防火墙、站点解析）：$FILE_URL"

  log "==> 6/7 下载并整理证书"
  mkdir -p cert
  curl -sS -L "https://api.zerossl.com/certificates/${CERT_ID}/download?access_key=${ACCESS_KEY}" -o cert.zip
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

  log "==> 7/7 完成并输出证书路径（可复制）"
  echo
  echo "证书路径（中文＋英文）:"
  echo "  服务器证书 / Server Certificate:        $LIVE_DIR/cert.crt"
  echo "  私钥 / Private Key:                     $LIVE_DIR/privkey.key"
  echo "  中间证书 / CA Bundle:                   $LIVE_DIR/ca_bundle.crt"
  echo "  整链 / Full Chain (cert+CA):            $LIVE_DIR/fullchain.pem"
  echo
  echo "Nginx 示例（配置一次，续签覆盖同路径）:"
  echo "  ssl_certificate     $LIVE_DIR/fullchain.pem;"
  echo "  ssl_certificate_key $LIVE_DIR/privkey.key;"
  echo
}

# ------------------- 自动续签安装 -------------------
install_systemd() {
  as_root || return 1
  local svc="/etc/systemd/system/zerossl-${MODE}-${TARGET//\//_}.service"
  local tim="/etc/systemd/system/zerossl-${MODE}-${TARGET//\//_}.timer"

  cat > "$svc" <<EOF
[Unit]
Description=ZeroSSL ${MODE} cert renew for ${TARGET}
After=network-online.target

[Service]
Type=oneshot
EnvironmentFile=${ENV_FILE}
ExecStart=/usr/bin/env bash -c 'ACCESS_KEY="\${ACCESS_KEY}" MODE="\${MODE}" TARGET="\${TARGET}" VALID_DAYS="\${VALID_DAYS}" WEBROOT="\${WEBROOT}" LIVE_DIR="\${LIVE_DIR}" STATE_DIR="\${STATE_DIR}" CONFIG_DIR="\${CONFIG_DIR}" bash "\$0" --renew'
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
  # 每月 1 日 03:17 执行
  local abs_self
  abs_self="$(readlink -f "$0")"
  local line="17 3 1 * * ACCESS_KEY=$(printf %q "$ACCESS_KEY") MODE=$(printf %q "$MODE") TARGET=$(printf %q "$TARGET") VALID_DAYS=$(printf %q "$VALID_DAYS") WEBROOT=$(printf %q "$WEBROOT") LIVE_DIR=$(printf %q "$LIVE_DIR") STATE_DIR=$(printf %q "$STATE_DIR") CONFIG_DIR=$(printf %q "$CONFIG_DIR") /usr/bin/env bash $abs_self --renew >> /var/log/zerossl_renew.log 2>&1"
  (crontab -l 2>/dev/null || true; echo "$line") | crontab -
  log "已安装 cron 定时任务：每月 1 日 03:17 尝试续签"
}

# ------------------- 主入口 -------------------
main() {
  if [[ "${1:-}" == "--renew" ]]; then
    # 续签模式：必须已有 .env
    [[ -f "$ENV_FILE" ]] || die "--renew 模式找不到 $ENV_FILE，请先运行一次完成初始化"
    # 重新计算路径（防止首次占位）
    recompute_paths_by_target
    # 直接签发一次并覆盖
    issue_once
    # nginx reload（若可用）
    if command -v nginx >/dev/null 2>&1; then
      nginx -t >/dev/null 2>&1 && (systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null) || true
    fi
    log "续签完成。"
    exit 0
  fi

  # 首次/常规运行：选择目标 + 获取 Access Key
  select_mode_and_target
  prompt_access_key_if_needed

  # 根据选择重算目录，保存 .env
  recompute_paths_by_target
  persist_env

  # 执行一次签发
  issue_once

  # 安装自动续签（优先 systemd）
  log "==> 正在安装自动续签..."
  if command -v systemctl >/dev/null 2>&1; then
    install_systemd || install_cron
  else
    install_cron
  fi
  log "自动续签安装完成。"

  # nginx reload（若可用）
  if command -v nginx >/dev/null 2>&1; then
    nginx -t >/dev/null 2>&1 && (systemctl reload nginx 2>/dev/null || nginx -s reload 2>/dev/null) || true
  fi

  log "全部完成。"
}

main "$@"
