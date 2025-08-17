#!/usr/bin/env bash
set -euo pipefail

# ======================================================================
# ZeroSSL 域名/IP 证书一键脚本
# 支持自动续签，支持域名证书与 IP 证书
# 修复点：在 CSR 生成时加入 -extensions v3_req，确保 SAN 生效
# ======================================================================

need_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "需要命令：$1"; exit 1; }; }
log()      { echo "[$(date '+%F %T')] $*"; }
die()      { echo "[$(date '+%F %T')] ERROR: $*" >&2; exit 1; }
as_root()  { [[ ${EUID:-$(id -u)} -eq 0 ]]; }

for c in curl jq openssl unzip; do need_cmd "$c"; done
need_cmd python3

ACCESS_KEY="${ACCESS_KEY:-}"
MODE="${MODE:-}"
TARGET="${TARGET:-}"
VALID_DAYS="${VALID_DAYS:-90}"
WEBROOT="${WEBROOT:-}"
KEY_TYPE="${KEY_TYPE:-rsa:2048}"

if as_root; then
  DEFAULT_BASE="/etc/zerossl-ip"
else
  DEFAULT_BASE="$HOME/.zerossl-ip"
fi

CONFIG_DIR="$DEFAULT_BASE/${TARGET:-placeholder}"
STATE_DIR="$CONFIG_DIR/state"
LIVE_DIR="$CONFIG_DIR/live"
ENV_FILE="$STATE_DIR/.env"

gen_key_and_csr() {
  local kt="$1"
  case "$kt" in
    rsa:* )
      local bits="${kt#rsa:}"; [[ -n "$bits" ]] || bits="2048"
      openssl req -new -newkey "rsa:${bits}" -nodes \
        -keyout server.key -out server.csr \
        -config openssl_san.cnf -extensions v3_req
      ;;
    ec:* )
      local curve="${kt#ec:}"; [[ -n "$curve" ]] || curve="prime256v1"
      openssl ecparam -name "$curve" -genkey -noout -out server.key
      openssl req -new -key server.key -out server.csr \
        -config openssl_san.cnf -extensions v3_req
      ;;
    * ) die "不支持的 KEY_TYPE：$kt（示例：rsa:2048 或 ec:prime256v1）" ;;
  esac
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
    --data "certificate_domains=${TARGET}&certificate_validity_days=${VALID_DAYS}&strict_domains=1")"

  CERT_ID="$(echo "$CREATE_JSON" | jq -r '.id // .certificate.id // empty')"
  [[ -n "$CERT_ID" && "$CERT_ID" != "null" ]] || die "创建证书失败：$(echo "$CREATE_JSON")"
  log "证书ID：$CERT_ID"

  log "==> 3/7 获取验证信息"
  CERT_INFO="$(curl -fsS "https://api.zerossl.com/certificates/${CERT_ID}?access_key=${ACCESS_KEY}")"

  FILE_PATH="$(echo "$CERT_INFO" | jq -r ".validation.other_methods[\"$TARGET\"].file_validation_path")"
  FILE_CONTENT="$(echo "$CERT_INFO" | jq -r ".validation.other_methods[\"$TARGET\"].file_validation_content")"
  FILE_URL="$(echo "$CERT_INFO" | jq -r ".validation.other_methods[\"$TARGET\"].file_validation_url_http")"

  [[ -n "$FILE_PATH" && "$FILE_PATH" != "null" ]] || die "未能获取验证文件路径"

  log "验证文件URL：$FILE_URL"

  if [[ -n "${WEBROOT:-}" ]]; then
    mkdir -p "${WEBROOT}$(dirname "$FILE_PATH")"
    printf "%s" "$FILE_CONTENT" > "${WEBROOT}${FILE_PATH}"
  else
    WEBROOT="${WORKDIR}/webroot"
    mkdir -p "${WEBROOT}$(dirname "$FILE_PATH")"
    printf "%s" "$FILE_CONTENT" > "${WEBROOT}${FILE_PATH}"
    nohup python3 -m http.server 80 --bind 0.0.0.0 --directory "$WEBROOT" >/dev/null 2>&1 &
    SERVER_PID=$!
  fi

  log "==> 4/7 触发验证"
  curl -fsS -X POST "https://api.zerossl.com/certificates/${CERT_ID}/challenges?access_key=${ACCESS_KEY}" \
    --data "validation_method=HTTP_CSR_HASH" >/dev/null

  log "==> 5/7 轮询验证状态"
  for _ in $(seq 1 20); do
    STATUS="$(curl -fsS "https://api.zerossl.com/certificates/${CERT_ID}?access_key=${ACCESS_KEY}" | jq -r .status)"
    log "当前状态：$STATUS"
    [[ "$STATUS" == "issued" ]] && break
    sleep 5
  done

  [[ "$STATUS" == "issued" ]] || die "验证失败，请检查80端口/防火墙"

  log "==> 6/7 下载证书"
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

  log "==> 7/7 完成"
  echo "证书路径："
  echo "  $LIVE_DIR/cert.crt"
  echo "  $LIVE_DIR/privkey.key"
  echo "  $LIVE_DIR/ca_bundle.crt"
  echo "  $LIVE_DIR/fullchain.pem"
}

main() {
  if [[ -z "${MODE:-}" || -z "${TARGET:-}" || -z "${ACCESS_KEY:-}" ]]; then
    echo "用法示例："
    echo "ACCESS_KEY=你的key MODE=ip TARGET=1.2.3.4 ./AutoSSL.sh"
    exit 1
  fi
  issue_once
}

main "$@"
