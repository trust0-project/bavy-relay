#!/bin/bash
# ── Development-only certificate generator ──────────────────────────────
# Generates short-lived self-signed certificates for local/dev WebTransport.
# Chrome/Chromium requires ≤14 days validity for serverCertificateHashes.
#
# For PRODUCTION, use Let's Encrypt (or any CA) certificates instead and
# mount them into the container. See docker-compose.yml and README.md.

set -e

CERTS_DIR="${1:-./certs}"
VALIDITY_DAYS="${VALIDITY_DAYS:-10}"  # Max 14 for Chrome; 10 gives margin

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ⚠  DEVELOPMENT ONLY — Self-Signed Certificate Generator   ║"
echo "║  For production, use Let's Encrypt / CA-signed certificates ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Output directory: $CERTS_DIR"
echo "Validity: $VALIDITY_DAYS days"

# Create certs directory if it doesn't exist
mkdir -p "$CERTS_DIR"

# Generate ECDSA P-256 key (required for short-lived certs in WebTransport)
openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS_DIR/relay-key.pem"

# Build SAN list — always include localhost + common local addresses
SAN="DNS:localhost,IP:127.0.0.1,IP:::1,DNS:relay,IP:10.0.2.2"
if [ -n "$RELAY_DOMAIN" ]; then
    SAN="${SAN},DNS:${RELAY_DOMAIN}"
    echo "Including domain: $RELAY_DOMAIN"
fi

# Generate self-signed certificate
openssl req -new -x509 \
    -key "$CERTS_DIR/relay-key.pem" \
    -out "$CERTS_DIR/relay-cert.pem" \
    -days "$VALIDITY_DAYS" \
    -subj "/CN=localhost" \
    -addext "subjectAltName=${SAN}"

echo ""
echo "✓ Generated certificates:"
echo "  - $CERTS_DIR/relay-cert.pem"
echo "  - $CERTS_DIR/relay-key.pem"
echo "  - Valid for $VALIDITY_DAYS days"
echo ""

# Calculate SHA-256 hash of the certificate (DER format)
# This is what WebTransport serverCertificateHashes expects
CERT_HASH=$(openssl x509 -in "$CERTS_DIR/relay-cert.pem" -outform DER 2>/dev/null | \
    openssl dgst -sha256 -binary | \
    xxd -p -c 32 | \
    sed 's/\(..\)/\1:/g' | \
    sed 's/:$//')

echo "Certificate SHA-256 Hash (for WebTransport serverCertificateHashes):"
echo "$CERT_HASH"
echo ""

# Also output without colons for easy copy-paste
CERT_HASH_NO_COLONS=$(echo "$CERT_HASH" | tr -d ':')
echo "Hash without colons:"
echo "$CERT_HASH_NO_COLONS"
echo ""

# Show cert expiry
EXPIRY=$(openssl x509 -in "$CERTS_DIR/relay-cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
echo "Expires: $EXPIRY"
echo ""

echo "Usage:"
echo "  cargo run --release -- --cert-pem $CERTS_DIR/relay-cert.pem --key-pem $CERTS_DIR/relay-key.pem"
echo ""
echo "⚠  These certs expire in $VALIDITY_DAYS days. Regenerate before expiry."
echo "   For production, mount Let's Encrypt certs — see README.md"
