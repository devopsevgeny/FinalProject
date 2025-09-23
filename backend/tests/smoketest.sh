#!/usr/bin/env bash
# ConfMgr end-to-end smoke: health → secret v1 → read → rotate → read v1 → config → read
# + DB introspection: show raw nonce/ciphertext/checksum from Postgres
set -Eeuo pipefail

# ---- settings ---------------------------------------------------------------
BASE="${BASE:-http://localhost:8080}"        # API base
SECRET_PATH="${SECRET_PATH:-service/api}"    # secret logical path
CONFIG_PATH="${CONFIG_PATH:-app/feature-flags}"
ACTOR_ID="${ACTOR_ID:-$(uuidgen)}"           # who performs write actions
ACTOR_SUBJECT="${ACTOR_SUBJECT:-smoke-test}" # human-readable subject

# Resolve API_KEY:
# 1) use exported API_KEY if present
# 2) try to read from running backend container env
# 3) fallback to local .env (if any)
API_KEY="${API_KEY:-}"
if [[ -z "${API_KEY}" ]]; then
  if docker compose ps backend >/dev/null 2>&1; then
    API_KEY="$(docker compose exec -T backend sh -lc 'printf %s "$API_KEY"' || true)"
  fi
fi
if [[ -z "${API_KEY}" && -f .env ]]; then
  API_KEY="$(grep -E '^API_KEY=' .env | sed 's/^API_KEY=//')"
fi
if [[ -z "${API_KEY}" ]]; then
  echo "ERROR: API_KEY is not set. Export API_KEY=... or ensure backend container has it." >&2
  exit 1
fi

# Helpers
bold()  { printf "\033[1m%s\033[0m\n" "$*"; }
hr()    { printf -- "-----------------------------------------------------------------\n"; }
jqc()   { command -v jq >/dev/null && jq . || cat; }

http_json() {
  # Usage: http_json METHOD URL [JSON_BODY]
  local method="$1"; shift
  local url="$1"; shift
  local data="${1:-}"

  bold "==> ${method} ${url}"
  if [[ -n "${data}" ]]; then
    resp="$(curl -sS -w $'\n%{http_code}' -X "${method}" \
      -H "Content-Type: application/json" \
      -H "X-API-Key: ${API_KEY}" \
      -H "X-Actor-Id: ${ACTOR_ID}" \
      -H "X-Actor-Subject: ${ACTOR_SUBJECT}" \
      -d "${data}" "${url}")"
  else
    resp="$(curl -sS -w $'\n%{http_code}' -X "${method}" \
      -H "X-API-Key: ${API_KEY}" "${url}")"
  fi

  body="${resp%$'\n'*}"
  code="${resp##*$'\n'}"
  echo "(HTTP ${code})"
  echo "${body}" | jqc
  [[ "${code}" =~ ^20[01]$ ]] || { echo "Request failed"; exit 1; }
}

psql_show_secrets() {
  # Show raw encrypted secret versions for $SECRET_PATH (nonce/ciphertext base64)
  local q="
select
  si.path,
  sv.version,
  sv.is_current,
  encode(sv.nonce, 'base64')  as nonce_b64,
  encode(sv.ciphertext, 'base64') as ciphertext_b64,
  sv.alg,
  (si.path || '|' || sv.version)::text as aad_hint,
  sv.created_at,
  sv.created_by
from core.secret_items si
join core.secret_versions sv on sv.item_id = si.id
where si.path = '${SECRET_PATH}'
order by sv.version;
"
  bold "# DB: secret raw rows (${SECRET_PATH})"
  docker compose exec -T postgres bash -lc \
    "gosu postgres psql -d postgres -X -q -x -c \"${q//$'\n'/ }\"" || {
      echo "WARN: failed to query Postgres (is 'postgres' service up?)"
    }
}

psql_show_configs() {
  # Show config versions (checksum hex) for $CONFIG_PATH
  local q="
select
  ci.path,
  cv.version,
  cv.is_current,
  encode(cv.checksum,'hex') as checksum_hex,
  cv.value_json,
  cv.created_at,
  cv.created_by
from core.config_items ci
join core.config_versions cv on cv.item_id = ci.id
where ci.path = '${CONFIG_PATH}'
order by cv.version;
"
  bold "# DB: config raw rows (${CONFIG_PATH})"
  docker compose exec -T postgres bash -lc \
    "gosu postgres psql -d postgres -X -q -x -c \"${q//$'\n'/ }\"" || {
      echo "WARN: failed to query Postgres (is 'postgres' service up?)"
    }
}


# ---- run --------------------------------------------------------------------
hr
bold "=== ConfMgr Full Smoke ==="
echo "BASE=${BASE}"
echo "SECRET_PATH=${SECRET_PATH}"
echo "CONFIG_PATH=${CONFIG_PATH}"
echo "ACTOR_ID=${ACTOR_ID}"
echo "ACTOR_SUBJECT=${ACTOR_SUBJECT}"
echo "API_KEY=<hidden>"
hr

bold "#1 Health"
http_json GET "${BASE}/health"
hr

bold "#2 Create secret v1"
http_json POST "${BASE}/secret/${SECRET_PATH}" \
'{"value":{"username":"alice","password":"s3cr3t"}}'
hr

bold "#3 Read current secret"
http_json GET "${BASE}/secret/${SECRET_PATH}"
hr

bold "#4 Rotate secret (create v2)"
http_json POST "${BASE}/secret/${SECRET_PATH}" \
'{"value":{"username":"alice","password":"n3wS3cr3t"}}'
hr

bold "#5 Read secret version=1"
http_json GET "${BASE}/secret/${SECRET_PATH}?version=1"
hr

bold "#6 Create config v1"
http_json POST "${BASE}/config/${CONFIG_PATH}" \
'{"value":{"beta_ui":true,"limit":50}}'
hr

bold "#7 Read config current"
http_json GET "${BASE}/config/${CONFIG_PATH}"
hr

psql_show_secrets
hr
psql_show_configs
hr

bold "✓ Full smoke finished OK."