#!/bin/sh
# Generates a self-signed TLS certificate for local Docker development.
# In production, replace with Let's Encrypt via certbot or Caddy.
# Usage: sh gen-local-cert.sh [hostname]
#
# Output: deploy/nginx/certs/server.crt + server.key

DOMAIN="${1:-localhost}"
OUT="$(dirname "$0")/certs"
mkdir -p "$OUT"

echo "Generating self-signed TLS certificate for: $DOMAIN"

openssl req -x509 -newkey rsa:4096 -sha256 \
  -days 365 \
  -nodes \
  -keyout "$OUT/server.key" \
  -out "$OUT/server.crt" \
  -subj "/CN=$DOMAIN/O=SecureShareFR Dev/C=US" \
  -extensions san \
  -config <(cat <<EOF
[req]
distinguished_name = req_distinguished_name
[req_distinguished_name]
[san]
subjectAltName = DNS:$DOMAIN, DNS:localhost, IP:127.0.0.1
EOF
)

echo "Certificate generated:"
echo "  $OUT/server.crt"
echo "  $OUT/server.key"
echo ""
echo "To trust this certificate in your browser:"
echo "  Chrome/Edge: Import $OUT/server.crt into Trusted Root CAs"
echo "  Firefox: about:preferences#privacy -> Certificates -> View Certificates -> Import"
echo "  macOS:   sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain $OUT/server.crt"
echo "  Linux:   sudo cp $OUT/server.crt /usr/local/share/ca-certificates/secureshare.crt && sudo update-ca-certificates"
