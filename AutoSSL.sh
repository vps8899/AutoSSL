#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZeroSSL 域名/IP 证书一键脚本 - 安装器（适合放到 GitHub，VPS 一键执行）
# 作用：
#   1) 检测并安装依赖（curl jq openssl unzip python3）
#   2) 安装主脚本到 /usr/local/bin/zerossl_ip_oneclick_cn.sh
#   3) 立即启动主脚本（支持交互；也支持通过环境变量非交互执行）
#
# 用法（推荐）：
#   bash oneclick_install.sh
#
# 非交互示例（在执行前/执行时传入环境变量）：
#   ACCESS_KEY="xxx" MODE="domain" TARGET="www.example.com" bash oneclick_install.sh
#   ACCESS_KEY="xxx" MODE="ip"     TARGET="203.0.113.10"    bash oneclick_install.sh
#
# 变量（可选）：
#   WEBROOT=/var/www/html
#   LIVE_DIR=/etc/zerossl-ip/<target>/live
#   VALID_DAYS=90
#   KEY_TYPE=rsa:2048 或 ec:prime256v1
#   DEBUG=0/1
#
# 脚本可重复执行；主程序会负责 systemd/cron 定时续签的安装与更新。
# ============================================================================

as_root() { [[ ${EUID:-$(id -u)} -eq 0 ]]; }
need_cmd() { command -v "$1" >/dev/null 2>&1; }
say() { printf "%s\n" "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }

# 尝试使用 sudo 提权
ensure_root() {
  if as_root; then return 0; fi
  if need_cmd sudo; then
    exec sudo -E bash "$0" "$@"
  else
    die "需要 root 权限，请以 root 运行，或先安装 sudo。"
  fi
}

detect_pm() {
  if need_cmd apt-get;   then echo apt;   return; fi
  if need_cmd dnf;       then echo dnf;   return; fi
  if need_cmd yum;       then echo yum;   return; fi
  if need_cmd apk;       then echo apk;   return; fi
  if need_cmd pacman;    then echo pacman;return; fi
  echo "unknown"
}

install_deps() {
  local pm; pm="$(detect_pm)"
  say "==> 检测到包管理器：$pm"
  case "$pm" in
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y curl jq openssl unzip python3 ca-certificates
      update-ca-certificates || true
      ;;
    dnf)
      dnf install -y curl jq openssl unzip python3 ca-certificates
      update-ca-trust || true
      ;;
    yum)
      # 适配老系统：先装 epel 以获取 jq/python3
      yum install -y epel-release || true
      yum install -y curl jq openssl unzip python3 ca-certificates || {
        # 某些极老系统用 python36 包名
        yum install -y python36 || true
        need_cmd python3 || die "无法安装 python3，请手动安装后重试。"
      }
      update-ca-trust || true
      ;;
    apk)
      apk add --no-cache curl jq openssl unzip python3 ca-certificates
      update-ca-certificates || true
      ;;
    pacman)
      pacman -Sy --noconfirm curl jq openssl unzip python
      ;;
    *)
      for b in curl jq openssl unzip python3; do
        need_cmd "$b" || die "未能自动识别包管理器，请手动安装依赖：curl jq openssl unzip python3"
      done
      ;;
  esac
}

install_main_script() {
  local dst="/usr/local/bin/zerossl_ip_oneclick_cn.sh"
  say "==> 写入主脚本到 $dst"
  umask 022
  # 注意：这里使用 'EOF_SCRIPT'（带引号）避免变量在写入时被展开
  cat > "$dst" <<'EOF_SCRIPT'
#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# ZeroSSL 域名/IP 证书一键脚本（签发 + 自动续签, 中文交互）
# - 兼容非交互（通过环境变量传参）
# - 自动安装 systemd timer 或 cron，便于无人值守续签
# - 修复与强化：trap 不再互相覆盖；systemd 单元使用脚本绝对路径；权限更稳健
#   新增：KEY_TYPE（rsa:2048 / ec:prime256v1），DEBUG 开关，IPv6 支持
# ============================================================================

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "需要命令：$1"; exit 1; }; }
log()      { printf "%s\n" "$*"; }
die()      { echo "ERROR: $*" >&2; exit 1; }
as_root()  { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

for c in curl jq openssl unzip; do need_cmd "$c"; done
if [[ -z "${WEBROOT:-}" ]]; then
  need_cmd python3 || die "未检测到 python3，且未提供 WEBROOT；无法临时起 80 端口验证服务"
fi

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
  [[ -n "$ACCESS_KEY" ]] || die "ACCESS_KEY 不能为空"
}

recompute_paths_by_target() {
  local safe_target
  safe_target="${TARGET//\//_}"
  local base="$DEFAULT_BASE"
  CONFIG_DIR="${CONFIG_DIR:-$base/$safe_target}"
  STATE_DIR="${STATE_DIR:-$CONFIG_DIR/state}"
  LIVE_DIR="${LIVE_DIR:-$CONFIG_DIR/live}"
  ENV_FILE="$STATE_DIR/.env"
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
DEBUG="${DEBUG}"
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
    * )
      die "不支持的 KEY_TYPE：$kt（示例：rsa:2048 或 ec:prime256v1）"
      ;;
  esac
  debug "使用 KEY_TYPE=$kt"
}

issue_once() {
  WORKDIR="$(mktemp -d -t zerossl_${MODE}_${TARGET//\//_}_XXXX)"
  cd "$WORKDIR"

  log "==> 1/7 生成私钥与 CSR (SAN=${MODE^^}:${TARGET})"
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
    --data "certificate_domains=${TARGET}&certificate_validity_days=${VALID_DAYS}&strict_domains=1")" || true

  CERT_ID="$(echo "$CREATE_JSON" | jq -r '.id // .certificate.id // empty')"
  if [[ -z "${CERT_ID:-}" || "$CERT_ID" == "null" ]]; then
    echo "$CREATE_JSON" | jq . || true
    die "创建证书失败（可能是配额、目标不可用等）。"
  fi
  log "证书ID：$CERT_ID"

  log "==> 3/7 获取 HTTP 文件验证信息"
  CERT_INFO="$(curl -fsS "https://api.zerossl.com/certificates/${CERT_ID}?access_key=${ACCESS_KEY}")"
  VALID_NODE="$(echo "$CERT_INFO" | jq -r --arg t "$TARGET" '.validation.other_methods[$t]')"
  if [[ -z "$VALID_NODE" || "$VALID_NODE" == "null" ]]; then
    echo "$CERT_INFO" | jq . || true
    die "未找到验证信息（请确认 TARGET 已解析到本机公网IP/IPv6，且 80 端口对外开放）"
  fi
  FILE_PATH="$(echo "$VALID_NODE" | jq -r '.file_validation_path')"
  FILE_CONTENT="$(echo "$VALID_NODE" | jq -r '.file_validation_content')"
  FILE_URL="$(echo "$VALID_NODE" | jq -r '.file_validation_url_http')"

  log "验证文件URL：$FILE_URL"
  log "验证文件相对路径：$FILE_PATH"

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
    else
      die "需要 root 权限以监听 80 端口，或设置 WEBROOT 指向现有站点"
    fi
  fi

  log "==> 5/7 触发验证并轮询状态"
  curl -fsS -X POST "https://api.zerossl.com/certificates/${CERT_ID}/challenges?access_key=${ACCESS_KEY}" \
    --data "validation_method=HTTP_CSR_HASH" >/dev/null

  STATUS=""
  for _ in $(seq 1 36); do
    STATUS_JSON="$(curl -fsS "https://api.zerossl.com/certificates/${CERT_ID}/status?access_key=${ACCESS_KEY}" || true)"
    if [[ -z "$STATUS_JSON" || "$STATUS_JSON" == "Not Found" ]]; then
      STATUS_JSON="$(curl -fsS "https://api.zerossl.com/verification/status?access_key=${ACCESS_KEY}&certificate_id=${CERT_ID}" || true)"
    fi
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
  local line="17 3 1 * * ACCESS_KEY=$(printf %q "$ACCESS_KEY") MODE=$(printf %q "$MODE") TARGET=$(printf %q "$TARGET") VALID_DAYS=$(printf %q "$VALID_DAYS") WEBROOT=$(printf %q "$WEBROOT") LIVE_DIR=$(printf %q "$LIVE_DIR") STATE_DIR=$(printf %q "$STATE_DIR") CONFIG_DIR=$(printf %q "$CONFIG_DIR") KEY_TYPE=$(printf %q "$KEY_TYPE") DEBUG=$(printf %q "$DEBUG") /usr/bin/env bash $script_path --renew >> /var/log/zerossl_renew.log 2>&1"
  (crontab -l 2>/dev/null || true; echo "$line") | crontab -
  log "已安装 cron 定时任务：每月 1 日 03:17 尝试续签"
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
EOF_SCRIPT

  chmod +x "$dst"
  say "主脚本安装完成：$dst"
}

run_main_script() {
  say "==> 启动主脚本（首次运行将引导你完成签发并自动安装续签任务）"
  /usr/local/bin/zerossl_ip_oneclick_cn.sh
}

# ====== 主流程 ======
ensure_root "$@"
install_deps
install_main_script
run_main_script
