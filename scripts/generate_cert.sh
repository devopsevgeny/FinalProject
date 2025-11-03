#!/usr/bin/env bash
set -euo pipefail

# --- Settings (override via env) ---
: "${CA_CN:=confmgr-ca}"
: "${SERVER_CN:=postgres}"
: "${CLIENT_CN:=confmgr-app}"

# Validity (days)
: "${CA_DAYS:=3650}"
: "${CERT_DAYS:=365}"

# Output directory = script's directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# --- Helpers ---
need() { command -v "$1" >/dev/null 2>&1 || { echo "Error: '$1' not found"; exit 1; }; }
need openssl

force="${1:-}"   # use '-f' to overwrite
umask 077        # ensure new files are created private by default

# --- Files ---
CA_KEY="ca.key"
CA_CRT="ca.crt"
CA_SRL="ca.srl"

SERVER_KEY="server.key"
SERVER_CSR="server.csr"
SERVER_CRT="server.crt"
SERVER_EXT="server.ext"

CLIENT_KEY="client.key"
CLIENT_CSR="client.csr"
CLIENT_CRT="client.crt"
CLIENT_EXT="client.ext"

# --- Guard against accidental overwrite ---
exists_any() {
  [[ -f "$CA_KEY" || -f "$CA_CRT" || -f "$SERVER_KEY" || -f "$SERVER_CRT" || -f "$CLIENT_KEY" || -f "$CLIENT_CRT" ]]
}

if exists_any && [[ "$force" != "-f" && "$force" != "--force" ]]; then
  echo "Some cert files already exist in $(pwd). Use '-f' to overwrite:"
  ls -1 $CA_KEY $CA_CRT $SERVER_KEY $SERVER_CRT $CLIENT_KEY $CLIENT_CRT 2>/dev/null || true
  exit 1
fi

# Clean previous artifacts if forcing
if [[ "$force" == "-f" || "$force" == "--force" ]]; then
  rm -f "$CA_KEY" "$CA_CRT" "$CA_SRL" \
        "$SERVER_KEY" "$SERVER_CSR" "$SERVER_CRT" "$SERVER_EXT" \
        "$CLIENT_KEY" "$CLIENT_CSR" "$CLIENT_CRT" "$CLIENT_EXT"
fi

echo "[certs] Generating CA ($CA_CN) ..."
openssl genrsa -out "$CA_KEY" 4096
openssl req -x509 -new -nodes -key "$CA_KEY" -sha256 -days "$CA_DAYS" \
  -subj "/CN=$CA_CN" -out "$CA_CRT"

# --- Server certificate (Postgres) ---
# SANs include docker hostname 'postgres', loopbacks and service-friendly names.
cat > "$SERVER_EXT" <<EOF
subjectAltName = DNS:postgres, DNS:localhost, IP:127.0.0.1, IP:::1
extendedKeyUsage = serverAuth
EOF

echo "[certs] Generating server cert (CN=$SERVER_CN) ..."
openssl genrsa -out "$SERVER_KEY" 2048
openssl req -new -key "$SERVER_KEY" -out "$SERVER_CSR" -subj "/CN=$SERVER_CN"
openssl x509 -req -in "$SERVER_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$SERVER_CRT" -days "$CERT_DAYS" -sha256 -extfile "$SERVER_EXT"

# --- Client certificate (backend/app) ---
cat > "$CLIENT_EXT" <<EOF
extendedKeyUsage = clientAuth
EOF

echo "[certs] Generating client cert (CN=$CLIENT_CN) ..."
openssl genrsa -out "$CLIENT_KEY" 2048
openssl req -new -key "$CLIENT_KEY" -out "$CLIENT_CSR" -subj "/CN=$CLIENT_CN"
openssl x509 -req -in "$CLIENT_CSR" -CA "$CA_CRT" -CAkey "$CA_KEY" -CAcreateserial \
  -out "$CLIENT_CRT" -days "$CERT_DAYS" -sha256 -extfile "$CLIENT_EXT"

# --- Permissions (what Postgres expects) ---
# server.key must be owner-readable only; certs can be world-readable.
chmod 600 "$SERVER_KEY" "$CLIENT_KEY" "$CA_KEY"
chmod 644 "$SERVER_CRT" "$CLIENT_CRT" "$CA_CRT" "$SERVER_EXT" "$CLIENT_EXT"
# CA serial can be world-readable
[ -f "$CA_SRL" ] && chmod 644 "$CA_SRL"

# --- Verify chain ---
echo "[certs] Verifying ..."
openssl verify -CAfile "$CA_CRT" "$SERVER_CRT" >/dev/null && echo "  server.crt: OK"
openssl verify -CAfile "$CA_CRT" "$CLIENT_CRT" >/dev/null && echo "  client.crt: OK"

echo
echo "[certs] Done. Files generated in $(pwd):"
ls -l "$CA_CRT" "$CA_KEY" "$SERVER_CRT" "$SERVER_KEY" "$CLIENT_CRT" "$CLIENT_KEY"
echo
echo "Use these in docker-compose:"
echo "  postgres:"
echo "    volumes:"
echo "      - ./certs:/certs:ro"
echo "  backend:"
echo "    volumes:"
echo "      - ./certs/ca.crt:/run/certs/ca.crt:ro"
echo "      - ./certs/client.crt:/run/certs/client.crt:ro"
echo "      - ./certs/client.key:/run/certs/client.key:ro"
echo
echo "If Postgres logs 'certificate must be owned by postgres or root', your entrypoint should chown to postgres."

