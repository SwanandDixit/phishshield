#!/usr/bin/env bash
# PhishShield – TLS Certificate Generator (Linux/macOS)
# Run: bash scripts/gen_certs.sh
set -euo pipefail

CERTS_DIR="${1:-certs}"
HOSTNAME="${2:-localhost}"
VALID_DAYS=365

mkdir -p "$CERTS_DIR"

echo "Generating CA private key..."
openssl genrsa -out "$CERTS_DIR/ca.key" 4096

echo "Generating CA certificate..."
openssl req -new -x509 -days $VALID_DAYS -key "$CERTS_DIR/ca.key" \
  -out "$CERTS_DIR/ca.crt" \
  -subj "/C=IN/ST=Maharashtra/L=Mumbai/O=ZeroTrace-SPIT/CN=PhishShield-CA"

echo "Generating server private key..."
openssl genrsa -out "$CERTS_DIR/server.key" 2048

echo "Generating server CSR..."
openssl req -new -key "$CERTS_DIR/server.key" -out "$CERTS_DIR/server.csr" \
  -subj "/C=IN/ST=Maharashtra/L=Mumbai/O=ZeroTrace-SPIT/CN=$HOSTNAME"

echo "Signing server certificate..."
openssl x509 -req -days $VALID_DAYS \
  -in "$CERTS_DIR/server.csr" \
  -CA "$CERTS_DIR/ca.crt" \
  -CAkey "$CERTS_DIR/ca.key" \
  -CAcreateserial \
  -out "$CERTS_DIR/server.crt" \
  -extfile <(printf "[SAN]\nsubjectAltName=DNS:%s,DNS:localhost,IP:127.0.0.1" "$HOSTNAME") \
  -extensions SAN

rm -f "$CERTS_DIR/server.csr"
echo ""
echo "✓ Certificates generated in $CERTS_DIR/"
echo "  CA cert:     $CERTS_DIR/ca.crt"
echo "  Server cert: $CERTS_DIR/server.crt"
echo "  Server key:  $CERTS_DIR/server.key"
echo ""
echo "Trust the CA: sudo cp $CERTS_DIR/ca.crt /usr/local/share/ca-certificates/phishshield-ca.crt && sudo update-ca-certificates"
