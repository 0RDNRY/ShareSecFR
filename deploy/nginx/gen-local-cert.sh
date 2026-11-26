#!/bin/sh
# Generates a self-signed TLS certificate for local Docker development.
# For production, use Let's Encrypt (certbot) or Caddy's automatic ACME.
# Usage: sh gen-local-cert.sh [hostname]
#
# Output: deploy/nginx/certs/server.crt + server.key

set -eu

DOMAIN="${1:-localhost}"
OUT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)/certs"
mkdir -p "$OUT"

echo "Generating self-signed TLS certificate for: $DOMAIN"

# POSIX sh: no process substitution (<(...)), so write the OpenSSL config to a
# temporary file and remove it afterwards.
CFG="$(mktemp)"
trap 'rm -f "$CFG"' EXIT HUP INT TERM
cat > "$CFG" <<EOF
[req]
distinguished_name = req_distinguished_name
x509_extensions = san
prompt = no

[req_distinguished_name]
CN = $DOMAIN
O = SecureShareFR Dev
C = US

[san]
subjectAltName = DNS:$DOMAIN, DNS:localhost, IP:127.0.0.1
basicConstraints = critical, CA:TRUE
keyUsage = critical, digitalSignature, keyEncipherment, keyCertSign
extendedKeyUsage = serverAuth
EOF

openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout "$OUT/server.key" \
  -out "$OUT/server.crt" \
  -config "$CFG"

chmod 600 "$OUT/server.key"
chmod 644 "$OUT/server.crt"

echo "Certificate generated:"
echo "  $OUT/server.crt"
echo "  $OUT/server.key"
echo ""
echo "To trust this certificate in your browser:"
echo "  Import $OUT/server.crt into your OS/browser Trusted Root CAs"
echo "  Postman: Settings → SSL certificate verification → off (local only), or add the cert as a CA"
