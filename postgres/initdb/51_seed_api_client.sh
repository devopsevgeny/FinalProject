#!/usr/bin/env bash
set -euo pipefail

# This script runs only on first cluster init (docker-entrypoint-initdb.d)
: "${POSTGRES_DB:=postgres}"
: "${POSTGRES_USER:=postgres}"

CLIENT_ID="${CLIENT_ID:-}"
CLIENT_SECRET="${CLIENT_SECRET:-}"
ISSUER="${ISSUER:-}"   # optional; empty -> NULL

if [[ -z "$CLIENT_ID" || -z "$CLIENT_SECRET" ]]; then
  echo "[seed] CLIENT_ID/CLIENT_SECRET not provided, skipping seed."
  exit 0
fi

echo "[seed] Seeding api client '${CLIENT_ID}' (issuer='${ISSUER:-null}') ..."

# Insert or upsert with bcrypt hash (pgcrypto). Empty ISSUER => NULL.
psql -v ON_ERROR_STOP=1 \
    -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
    -v CLIENT_ID="$CLIENT_ID" \
    -v CLIENT_SECRET="$CLIENT_SECRET" \
    -v ISSUER="$ISSUER" <<'SQL'
-- Use psql variables and NULLIF to convert empty string to NULL
insert into core.api_clients(client_id, client_secret_hash, issuer, is_active)
values (
  :'CLIENT_ID',
  crypt(:'CLIENT_SECRET', gen_salt('bf', 12)),
  NULLIF(:'ISSUER',''),
  true
)
on conflict (client_id) do update
  set client_secret_hash = excluded.client_secret_hash,
      issuer             = excluded.issuer,
      is_active          = true;
SQL

echo "[seed] Done."

