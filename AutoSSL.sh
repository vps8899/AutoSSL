#!/usr/bin/env bash
set -Eeuo pipefail

# ====== 配置区 ======
ZEROSSL_API_KEY="${ZEROSSL_API_KEY:-YOUR_ZEROSSL_API_KEY}"
DOMAINS="${DOMAINS:-example.com,www.example.com}"     # 逗号分隔
WEBROOT="${WEBROOT:-/var/www/html}"                   # 必须能直达 /.well-known/pki-validation/
OUT_DIR="${OUT_DIR:-/etc/ssl/zerossl}"
VALIDITY_DAYS="${VALIDITY_DAYS:-90}"                  # 90 天免费证书
STRICT_WWW="${STRICT_WWW:-1}"                         # 1=不自动加/减 www

# ====== 依赖 ======
install_if_missing() {
  for p in curl jq openssl unzip; do
    command -v "$p" >/dev/null 2>&1 || {
      if command -v apt-get >/dev/null; then sudo apt-get update -y && sudo apt-get install -y "$p";
      elif command -v dnf >/dev/null; then sudo dnf install -y "$p";
      elif command -v yum >/dev/null; then sudo yum install -y "$p";
      elif command -v apk >/dev/null; then sudo apk add --no-cache "$p";
      else echo "缺少依赖 $p，且无法自动安装"; exit 1; fi
    }
  done
}
install_if_missing

PRIMARY="$(echo "$DOMAINS" | cut -d, -f1)"
CERT_DIR="$OUT_DIR/$PRIMARY"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

mkdir -p "$WEBROOT/.well-known/pki-validation" "$CERT_DIR"

# ====== 生成私钥 + CSR（含 SAN）======
# 兼容 OpenSSL：通过临时配置写入 SAN
CNF="$TMP/openssl.cnf"
i=1; ALT=""
IFS=',' read -r -a arr <<< "$DOMAINS"
for d in "${arr[@]}"; do ALT+="DNS.$i = $d"$'\n'; i=$((i+1)); done
cat >"$CNF" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = $PRIMARY

[req_ext]
subjectAltName = @alt_names

[alt_names]
$ALT
EOF

openssl genrsa -out "$CERT_DIR/privkey.pem" 2048 >/dev/null 2>&1
openssl req -new -key "$CERT_DIR/privkey.pem" -out "$TMP/csr.pem" -config "$CNF" -extensions req_ext >/dev/null 2>&1

# ====== 1) 创建证书订单 ======
CREATE_JSON="$TMP/create.json"
curl -fsS -X POST "https://api.zerossl.com/certificates?access_key=$ZEROSSL_API_KEY" \
  --data-urlencode "certificate_csr=$(cat "$TMP/csr.pem")" \
  -d "certificate_domains=$DOMAINS" \
  -d "certificate_validity_days=$VALIDITY_DAYS" \
  -d "strict_domains=$STRICT_WWW" \
  > "$CREATE_JSON"

CERT_ID="$(jq -r '.id' "$CREATE_JSON")"
[ -n "$CERT_ID" ] || { echo "创建证书失败：$(cat "$CREATE_JSON")" >&2; exit 1; }

# ====== 2) 写入 HTTP 校验文件（每个域名一份）======
for d in "${arr[@]}"; do
  URL=$(jq -r --arg d "$d" '.validation.other_methods[$d].file_validation_url_http' "$CREATE_JSON")
  CONTENT=$(jq -r --arg d "$d" '.validation.other_methods[$d].file_validation_content | join("\n")' "$CREATE_JSON")
  [ -n "$URL" ] && [ -n "$CONTENT" ] || { echo "获取 $d 校验信息失败"; exit 1; }
  FNAME="$(basename "$URL")"
  DEST="$WEBROOT/.well-known/pki-validation/$FNAME"
  printf "%s" "$CONTENT" | tee "$DEST" >/dev/null
done

# ====== 3) 触发域名验证（HTTP 文件方式）======
# 注：Verify Domains 端点用于重新/触发验证；HTTP 文件路径禁止 3xx 跳转。
curl -fsS -X POST "https://api.zerossl.com/certificates/$CERT_ID/challenges?access_key=$ZEROSSL_API_KEY" \
  -d "validation_method=HTTP_CSR_HASH" >/dev/null

# ====== 4) 轮询到签发（状态变为 issued）======
for i in $(seq 1 90); do
  STATUS_JSON="$(curl -fsS "https://api.zerossl.com/certificates/$CERT_ID?access_key=$ZEROSSL_API_KEY")"
  STATUS="$(echo "$STATUS_JSON" | jq -r '.status')"
  if [ "$STATUS" = "issued" ]; then
    break
  elif [ "$STATUS" = "cancelled" ] || [ "$STATUS" = "revoked" ]; then
    echo "证书状态异常：$STATUS_JSON" >&2; exit 1
  fi
  sleep 5
done

# ====== 5) 下载证书（ZIP），解压得到 crt / ca_bundle 等 ======
curl -fsS "https://api.zerossl.com/certificates/$CERT_ID/download?access_key=$ZEROSSL_API_KEY" \
  -o "$TMP/cert.zip"
unzip -qo "$TMP/cert.zip" -d "$CERT_DIR"

echo
echo "✅ 签发完成："
echo "  私钥     : $CERT_DIR/privkey.pem"
echo "  证书     : $CERT_DIR/certificate.crt"
echo "  CA 链    : $CERT_DIR/ca_bundle.crt"
echo "  主域     : $PRIMARY"
echo "  所有域   : $DOMAINS"
echo
echo "把证书/私钥路径写入你的 Web 服务器配置并 reload 即可。"
