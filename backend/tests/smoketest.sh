#!/usr/bin/env bash
# ConfMgr end-to-end smoke test with PASS/FAIL summary

# --- safety: keep running to collect all failures ---
set -u -o pipefail

# --- colors ---
GREEN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
bold() { printf "${BOLD}%s${NC}\n" "$*"; }
sep()  { printf -- "-----------------------------------------------------------------\n"; }
ok()   { printf "${GREEN}✓ %s${NC}\n" "$*"; }
fail() { printf "${RED}✗ %s${NC}\n" "$*"; }

# --- tmp workspace ---
TMP="$(mktemp -d)"
cleanup() { rm -rf "$TMP"; }
trap cleanup EXIT

# --- read .env if present (only for missing vars) ---
if [ -f "../../.env" ]; then
  # export only lines of the form KEY=VALUE without spaces
  while IFS='=' read -r k v; do
    [[ -z "${k:-}" || "$k" =~ ^# ]] && continue
    if [ -z "${!k:-}" ]; then export "$k"="$v"; fi
  done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "../../.env")
fi

# --- config ---
BASE="${BASE:-http://localhost:8080}"
SECRET_PATH="${SECRET_PATH:-service/api}"
CONFIG_PATH="${CONFIG_PATH:-app/feature-flags}"
ACTOR_ID="${ACTOR_ID:-$(uuidgen)}"
ACTOR_SUBJECT="${ACTOR_SUBJECT:-smoke-test}"
API_KEY="${API_KEY:-}"

# --- counters ---
TOTAL=0; PASS=0; FAIL=0
record_pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
record_fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }

# --- helpers ---
need() { command -v "$1" >/dev/null 2>&1 || { fail "missing tool: $1"; exit 2; }; }
need curl; need jq

if [ -z "${API_KEY}" ]; then
  fail "API_KEY is not set (export API_KEY=... or put API_KEY=... in .env)"
  exit 2
fi

hide_key="${API_KEY:0:6}…${API_KEY: -4}"

header() {
  sep
  bold "=== ConfMgr Full Smoke ==="
  echo "BASE=${BASE}"
  echo "SECRET_PATH=${SECRET_PATH}"
  echo "CONFIG_PATH=${CONFIG_PATH}"
  echo "ACTOR_ID=${ACTOR_ID}"
  echo "ACTOR_SUBJECT=${ACTOR_SUBJECT}"
  echo "API_KEY=<hidden:${hide_key}>"
  sep
}
header

# run_http METHOD URL [JSON] -> prints status; body saved in $OUT
run_http() {
  local method="$1" url="$2" json="${3:-}"
  OUT="$TMP/resp_$(date +%s%N).json"
  if [ -n "$json" ]; then
    status=$(curl -sS -w "%{http_code}" -o "$OUT" -X "$method" \
      -H "Content-Type: application/json" \
      -H "X-API-Key: ${API_KEY}" \
      -H "X-Actor-Id: ${ACTOR_ID}" \
      -H "X-Actor-Subject: ${ACTOR_SUBJECT}" \
      --data "$json" \
      "$url")
  else
    status=$(curl -sS -w "%{http_code}" -o "$OUT" -X "$method" \
      -H "X-API-Key: ${API_KEY}" \
      "$url")
  fi
  printf "(HTTP %s)\n" "$status"
}

assert_status() {
  local want="$1"
  if [ "$status" = "$want" ]; then
    record_pass
    ok "status $want"
  else
    record_fail
    fail "got HTTP $status, want $want"
    echo "Response body:"
    cat "$OUT" | sed 's/^/  /'
  fi
}

assert_jq() {
  local expr="$1" msg="$2"
  if jq -e "$expr" "$OUT" >/dev/null 2>&1; then
    record_pass
    ok "$msg"
  else
    record_fail
    fail "$msg"
    echo "Body did not match: jq '$expr'"
    cat "$OUT" | sed 's/^/  /'
  fi
}

step() { sep; bold "$1"; }

# 1) Health
step "#1 Health"
echo "==> GET ${BASE}/health"
run_http GET "${BASE}/health"
assert_status 200
assert_jq '.status=="ok"' "health OK"

# 2) Create secret v1
step "#2 Create secret v1"
payload_secret_v1='{"value":{"username":"alice","password":"s3cr3t"}}'
echo "==> POST ${BASE}/secret/${SECRET_PATH}"
run_http POST "${BASE}/secret/${SECRET_PATH}" "$payload_secret_v1"
assert_status 201
assert_jq '.path=="'"$SECRET_PATH"'"' "path matches"
assert_jq '.version|type=="number"' "version is number"

# 3) Read current secret
step "#3 Read current secret"
echo "==> GET ${BASE}/secret/${SECRET_PATH}"
run_http GET "${BASE}/secret/${SECRET_PATH}"
assert_status 200
assert_jq '.value.username=="alice"' "username=alice"
assert_jq '.value.password=="s3cr3t"' "password=s3cr3t"

# 4) Rotate secret (create v2)
step "#4 Rotate secret (create v2)"
payload_secret_v2='{"value":{"username":"alice","password":"n3wS3cr3t"}}'
echo "==> POST ${BASE}/secret/${SECRET_PATH}"
run_http POST "${BASE}/secret/${SECRET_PATH}" "$payload_secret_v2"
assert_status 201
assert_jq '.value.password=="n3wS3cr3t"' "rotated secret ok"

# 5) Read secret version=1
step "#5 Read secret version=1"
echo "==> GET ${BASE}/secret/${SECRET_PATH}?version=1"
run_http GET "${BASE}/secret/${SECRET_PATH}?version=1"
assert_status 200
assert_jq '.value.password=="s3cr3t"' "v1 password matches"

# 6) Create config v1
step "#6 Create config v1"
payload_cfg='{"value":{"beta_ui":true,"limit":50}}'
echo "==> POST ${BASE}/config/${CONFIG_PATH}"
run_http POST "${BASE}/config/${CONFIG_PATH}" "$payload_cfg"
assert_status 201
assert_jq '.value.beta_ui==true' "config flag set"

# 7) Read config current
step "#7 Read config current"
echo "==> GET ${BASE}/config/${CONFIG_PATH}"
run_http GET "${BASE}/config/${CONFIG_PATH}"
assert_status 200
assert_jq '.value.limit==50' "config limit=50"

# 8) DB: show raw encrypted rows
psql_show_secrets() {
  local q="
select
  si.path,
  sv.version,
  sv.is_current,
  encode(sv.nonce,'base64')      as nonce_b64,
  encode(sv.ciphertext,'base64') as ciphertext_b64,
  sv.alg,
  (si.path || '|' || sv.version)::text as aad_hint,
  sv.created_at,
  sv.created_by
from core.secret_items si
join core.secret_versions sv on sv.item_id=si.id
where si.path='${SECRET_PATH}'
order by sv.version;
"
  docker compose exec -T postgres bash -lc \
    "gosu postgres psql -d postgres -X -q -x -c \"${q//$'\n'/ }\""
}

psql_show_configs() {
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
join core.config_versions cv on cv.item_id=ci.id
where ci.path='${CONFIG_PATH}'
order by cv.version;
"
  docker compose exec -T postgres bash -lc \
    "gosu postgres psql -d postgres -X -q -x -c \"${q//$'\n'/ }\""
}

step "# DB: secret raw rows (${SECRET_PATH})"
if psql_show_secrets; then record_pass; ok "psql secret query ran"; else record_fail; fail "psql secret query failed"; fi

step "# DB: config raw rows (${CONFIG_PATH})"
if psql_show_configs; then record_pass; ok "psql config query ran"; else record_fail; fail "psql config query failed"; fi

# --- summary ---
sep
if [ "$FAIL" -eq 0 ]; then
  printf "${GREEN}✓ Full smoke finished OK. Passed: %d/%d${NC}\n" "$PASS" "$TOTAL"
  exit 0
else
  printf "${RED}✗ Smoke finished with failures. Passed: %d, Failed: %d, Total: %d${NC}\n" "$PASS" "$FAIL" "$TOTAL"
  exit 1
fi
