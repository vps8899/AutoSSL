# === 1) 生成一键脚本 ===
sudo tee /usr/local/bin/issue_zerossl.sh >/dev/null <<'BASH'
#!/usr/bin/env bash
set -Eeuo pipefail

# ===== 配置（按需用 env 覆盖）=====
ACCESS_KEY="${ACCESS_KEY:-YOUR_ZEROSSL_ACCESS_KEY}"   # ← 必填：ZeroSSL API Key
DOMAIN="${DOMAIN:-YOUR_DOMAIN}"                       # ← 必填：要签的域名
WEBROOT="${WEBROOT:-/var/www/html}"                   # HTTP 文件验证目录的站点根
OUT_DIR_ROOT="${OUT_DIR:-/etc/zerossl-auto}"          # 证书保存目录根
VALIDITY_DAYS="${VALIDITY_DAYS:-90}"                  # 免费证书 90 天
STRICT_WWW="${STRICT_WWW:-1}"

# ===== 依赖安装 =====
install_pkgs () {
  if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update -y
    sudo apt-get install -y curl jq openssl unzip ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y curl jq openssl unzip ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y curl jq openssl unzip ca-certificates
  elif command -v apk >/dev/null 2>&1; then
    sudo apk add --no-cache curl jq openssl unzip ca-certificates
  fi
}
for c in curl jq openssl unzip; do command -v "$c" >/dev/null 2>&1 || install_pkgs; done

# ===== 基本检查 =====
[[ -n "$ACCESS_KEY" && "$ACCESS_KEY" != "YOUR_ZEROSSL_ACCESS_KEY" ]] || { echo "请设置 ACCESS_KEY（ZeroSSL API Key）"; exit 1; }
[[ -n "$DOMAIN" && "$DOMAIN" != "YOUR_DOMAIN" ]] || { echo "请设置 DOMAIN（要签的域名）"; exit 1; }

# ZeroSSL API 连通性/Key 有效性
KEY_CHECK="$(curl -s "https://api.zerossl.com/certificates?access_key=$ACCESS_KEY" | jq -r '.success // "ok"')"
if [[ "$KEY_CHECK" == "false" ]]; then
  echo "ZeroSSL access_key 可能无效或账号未激活，请在控制台检查。"
  curl -s "https://api.zerossl.com/certificates?access_key=$ACCESS_KEY" | jq .
  exit 1
fi

# ===== 路径准备 =====
CERT_DIR="$OUT_DIR_ROOT/$DOMAIN"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

sudo install -d -m 755 "$CERT_DIR"
sudo install -d -m 755 "$WEBROOT/.well-known/pki-validation"

# ===== 生成私钥 + CSR（含 SAN）=====
OPENSSL_CNF="$TMP/openssl.cnf"
cat >"$OPENSSL_CNF" <<EOF
[req]
default_bits = 2048
prompt = no
default_md = sha256
req_extensions = req_ext
distinguished_name = dn

[dn]
CN = $DOMAIN

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DOMAIN
EOF

sudo openssl genrsa -out "$CERT_DIR/privkey.pem" 2048 >/dev/null 2>&1
sudo openssl req -new -key "$CERT_DIR/privkey.pem" -out "$TMP/csr.pem" -config "$OPENSSL_CNF" -extensions req_ext >/dev/null 2>&1

# ===== 1) 创建证书订单 =====
CREATE_JSON="$TMP/create.json"
curl -fsS -X POST "https://api.zerossl.com/certificates?access_key=$ACCESS_KEY" \
  --data-urlencode "certificate_csr=$(cat "$TMP/csr.pem")" \
  -d "certificate_domains=$DOMAIN" \
  -d "certificate_validity_days=$VALIDITY_DAYS" \
  -d "strict_domains=$STRICT_WWW" \
  > "$CREATE_JSON"

CERT_ID="$(jq -r '.id // empty' "$CREATE_JSON")"
[[ -n "$CERT_ID" ]] || { echo "创建证书失败："; cat "$CREATE_JSON" | jq .; exit 1; }

# ===== 2) 写入 HTTP 验证文件 =====
VAL_URL="$(jq -r --arg d "$DOMAIN" '.validation.other_methods[$d].file_validation_url_http // empty' "$CREATE_JSON")"
VAL_CONTENT="$(jq -r --arg d "$DOMAIN" '.validation.other_methods[$d].file_validation_content | join("\n")' "$CREATE_JSON")"
[[ -n "$VAL_URL" && -n "$VAL_CONTENT" ]] || { echo "未获取到验证信息（可能域名字符串不匹配）"; jq . "$CREATE_JSON"; exit 1; }

FNAME="$(basename "$VAL_URL")"
sudo tee "$WEBROOT/.well-known/pki-validation/$FNAME" >/dev/null <<<"$VAL_CONTENT"

# 自检：必须 200，且不要被 3xx 跳转
HTTP_CODE="$(curl -s -o /dev/null -w '%{http_code}' "http://$DOMAIN/.well-known/pki-validation/$FNAME")"
if [[ "$HTTP_CODE" != "200" ]]; then
  echo "验证文件访问异常（HTTP $HTTP_CODE）。请确保 80 端口直达且不跳转到 https："
  echo "  http://$DOMAIN/.well-known/pki-validation/$FNAME"
  exit 1
fi

# ===== 3) 触发域名验证 =====
VERIFY_JSON="$TMP/verify.json"
curl -fsS -X POST "https://api.zerossl.com/certificates/$CERT_ID/challenges?access_key=$ACCESS_KEY" \
  -d "validation_method=HTTP_CSR_HASH" > "$VERIFY_JSON" || true

# ===== 4) 轮询状态到 issued =====
echo "等待 ZeroSSL 验证签发（最多 3 分钟）..."
for i in $(seq 1 36); do
  STATUS_JSON="$(curl -s "https://api.zerossl.com/certificates/$CERT_ID?access_key=$ACCESS_KEY")"
  STATUS="$(echo "$STATUS_JSON" | jq -r '.status')"
  echo "  [$i/36] status: $STATUS"
  [[ "$STATUS" == "issued" ]] && break
  [[ "$STATUS" == "cancelled" || "$STATUS" == "revoked" ]] && { echo "$STATUS_JSON" | jq .; exit 1; }
  sleep 5
done
[[ "$STATUS" == "issued" ]] || { echo "未在预期时间内签发，请稍后重试或检查 80 端口/跳转规则。"; exit 1; }

# ===== 5) 下载证书 ZIP 并落盘 =====
ZIP="/tmp/$CERT_ID.zip"
curl -fsSL "https://api.zerossl.com/certificates/$CERT_ID/download?access_key=$ACCESS_KEY" -o "$ZIP"
sudo unzip -qo "$ZIP" -d "$CERT_DIR"

# 统一命名（可选）：生成 fullchain.pem
if [[ -f "$CERT_DIR/certificate.crt" && -f "$CERT_DIR/ca_bundle.crt" ]]; then
  sudo sh -c "cat '$CERT_DIR/certificate.crt' '$CERT_DIR/ca_bundle.crt' > '$CERT_DIR/fullchain.pem'"
fi

echo
echo "✅ 签发完成：$DOMAIN"
echo "  私钥         : $CERT_DIR/privkey.pem"
echo "  服务器证书   : $CERT_DIR/certificate.crt"
echo "  CA 链        : $CERT_DIR/ca_bundle.crt"
echo "  合并链(full) : $CERT_DIR/fullchain.pem"
echo
echo "Nginx 示例："
echo "  ssl_certificate     $CERT_DIR/fullchain.pem;"
echo "  ssl_certificate_key $CERT_DIR/privkey.pem;"
echo
echo "若你的 80 端口会强制跳转到 https，请务必在 http 虚拟主机里放行："
cat <<'NGINX'
server {
    listen 80;
    server_name YOUR_DOMAIN;
    root /var/www/html;
    location ^~ /.well-known/pki-validation/ { allow all; }
    # 其他规则（例如全站跳转）放在这下面，避免影响验证路径
}
NGINX
BASH

# === 2) 赋权 ===
sudo chmod +x /usr/local/bin/issue_zerossl.sh

# === 3) 运行（把下面两个值改成你的实际值再执行）===
sudo ACCESS_KEY="7e0671b0ec7897b8c3c2a741b623ae5b" DOMAIN="11.5216666.xyz" WEBROOT="/var/www/html" OUT_DIR="/etc/zerossl-auto" /usr/local/bin/issue_zerossl.sh
