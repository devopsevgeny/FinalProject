#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="$(dirname "${BASH_SOURCE[0]}")/../certs/frontend"
mkdir -p "$CERT_DIR"

SUBJECT=${1:-"CN=localhost"}
DAYS=${TLS_DAYS:-3650}

openssl req -x509 -nodes -newkey rsa:4096 \
  -keyout "$CERT_DIR/privkey.pem" \
  -out "$CERT_DIR/fullchain.pem" \
  -days "$DAYS" \
  -subj "/$SUBJECT"

echo "Self-signed certificate generated in $CERT_DIR"
