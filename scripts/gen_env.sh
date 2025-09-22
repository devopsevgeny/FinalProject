#!/usr/bin/env bash
set -euo pipefail

# Determine project root (one level above scripts/)
PROJECT_ROOT="$(dirname "$(dirname "$0")")"

TEMPLATE="$PROJECT_ROOT/.env.tmpl"
OUTPUT="$PROJECT_ROOT/.env"

# --- sanity checks ---
need() { command -v "$1" >/dev/null 2>&1 || { echo "Error: '$1' not found"; exit 1; }; }
need openssl
need uuidgen
need sed

if [[ ! -f "$TEMPLATE" ]]; then
  echo "Error: template not found: $TEMPLATE"
  echo "Create it with required placeholders: {{DATA_KEY_HEX}} {{API_KEY}} {{MASTER_KEY}} {{CLIENT_ID}} {{CLIENT_SECRET}} {{ISSUER}}"
  exit 1
fi

# Do not overwrite existing .env unless -f/--force is passed
FORCE="${1:-}"
if [[ -f "$OUTPUT" && "$FORCE" != "-f" && "$FORCE" != "--force" ]]; then
  echo "Refusing to overwrite existing $OUTPUT. Use '-f' to overwrite."
  exit 1
fi

# --- generate values ---
DATA_KEY_HEX="$(openssl rand -hex 32)"
MASTER_KEY="$(openssl rand -hex 32)"
CLIENT_ID="$(uuidgen)"
CLIENT_SECRET="$(openssl rand -hex 32)"
ISSUER="confmgr-$(openssl rand -hex 4)"
API_KEY_DEFAULT="dev-secret-api-key"

# --- render .env from template ---
# Note: values are hex/uuid; they don't contain slashes, so simple sed is safe.
sed \
  -e "s/{{DATA_KEY_HEX}}/$DATA_KEY_HEX/" \
  -e "s/{{API_KEY}}/$API_KEY_DEFAULT/" \
  -e "s/{{MASTER_KEY}}/$MASTER_KEY/" \
  -e "s/{{CLIENT_ID}}/$CLIENT_ID/" \
  -e "s/{{CLIENT_SECRET}}/$CLIENT_SECRET/" \
  -e "s/{{ISSUER}}/$ISSUER/" \
  "$TEMPLATE" > "$OUTPUT"

echo "[gen] .env created at $OUTPUT"
echo "  DATA_KEY_HEX=$DATA_KEY_HEX"
echo "  MASTER_KEY=$MASTER_KEY"
echo "  CLIENT_ID=$CLIENT_ID"
echo "  CLIENT_SECRET=$CLIENT_SECRET"
echo "  ISSUER=$ISSUER"
