#!/usr/bin/env bash
set -euo pipefail

CLIENT_ID=$(uuidgen)
CLIENT_SECRET=$(openssl rand -hex 32)
ISSUER="confmgr-$(openssl rand -hex 4)"

cat > .env <<EOF
# Postgres superuser
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=postgres

# API client seed (only used on first init)
CLIENT_ID=$CLIENT_ID
CLIENT_SECRET=$CLIENT_SECRET
ISSUER=$ISSUER
EOF

echo "[gen] .env created with:"
echo "CLIENT_ID=$CLIENT_ID"
echo "CLIENT_SECRET=$CLIENT_SECRET"
echo "ISSUER=$ISSUER"

