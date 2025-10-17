#!/usr/bin/env bash
# ConfMgr end-to-end smoke test (API Key and optional Bearer) with PASS/FAIL summary

set -Eeuo pipefail

GREEN='\033[0;32m'; RED='\033[0;31m'; YLW='\033[0;33m'; BOLD='\033[1m'; NC='\033[0m'
bold() { printf "${BOLD}%s${NC}\n" "$*"; }
sep()  { printf -- "-----------------------------------------------------------------\n"; }
ok()   { printf "${GREEN}✓ %s${NC}\n" "$*"; }
fail() { printf "${RED}✗ %s${NC}\n" "$*"; }

TMP="$(mktemp -d)"; cleanup() { rm -rf "$TMP"; }; trap cleanup EXIT

# load .env from repo root or current dir
load_env_file() {
  local envfile=""
  if   [ -f "../../.env" ]; then envfile="../../.env"
  elif [ -f ".env" ];      then envfile=".env"
  fi
  if [ -n "$envfile" ]; then
    while IFS='=' read -r k v; do
      [[ -z "${k:-}" || "$k" =~ ^# ]] && continue
      if [ -z "${!k:-}" ]; then export "$k"="$v"; fi
    done < <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$envfile")
  fi
}
load_env_file

# config
BASE="${BASE:-http://localhost:8080}"
SECRET_PATH="${SECRET_PATH:-service/api}"
CONFIG_PATH="${CONFIG_PATH:-app/feature-flags}"
ACTOR_ID="${ACTOR_ID:-$(uuidgen)}"
ACTOR_SUBJECT="${ACTOR_SUBJECT:-smoke-test}"

# auth
API_KEY="${API_KEY:-}"                  # from .env
LOGIN_USER="${LOGIN_USER:-admin}"
LOGIN_PASS="${LOGIN_PASS:-admin}"
RUN_BEARER="${RUN_BEARER:-0}"

# tools
need() { command -v "$1" >/dev/null 2>&1 || { fail "missing tool: $1"; exit 2; }; }
need curl; need jq

# bearer login
get_token() {
  TOKEN="$(curl -sS "${BASE}/auth/login" \
    -H 'Content-Type: application/json' \
    --data "{\"username\":\"${LOGIN_USER}\",\"password\":\"${LOGIN_PASS}\"}" \
    | jq -r .access_token)"
  if [ -z "${TOKEN:-}" ] || [ "${TOKEN}" = "null" ]; then
    fail "Bearer login failed. Check ${BASE}/auth/login and credentials."
    exit 2
  fi
}
[ "$RUN_BEARER" = "1" ] && get_token

mask() { local v="$1"; [ -z "$v" ] && { echo "none"; return; }; echo "${v:0:6}…${v: -4}"; }
sep; bold "=== ConfMgr Smoke Setup ==="
echo "BASE=${BASE}"
echo "SECRET_PATH=${SECRET_PATH}"
echo "CONFIG_PATH=${CONFIG_PATH}"
echo "ACTOR_ID=${ACTOR_ID}"
echo "ACTOR_SUBJECT=${ACTOR_SUBJECT}"
echo "API_KEY=<hidden:$(mask "${API_KEY:-}")>"
echo "TOKEN=<hidden:$(mask "${TOKEN:-}")>"
sep

# counters
TOTAL=0; PASS=0; FAIL=0
record_pass() { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); }
record_fail() { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); }

# http runner that switches auth per mode
# run_http MODE METHOD URL [JSON]
run_http() {
  local mode="$1" method="$2" url="$3" json="${4:-}"
  OUT="$TMP/resp_$(date +%s%N).json"
  local args=(-sS -w "%{http_code}" -o "$OUT" -X "$method")
  if [ -n "$json" ]; then
    args+=(-H "Content-Type: application/json" \
           -H "X-Actor-Id: ${ACTOR_ID}" \
           -H "X-Actor-Subject: ${ACTOR_SUBJECT}" \
           --data "$json")
  fi
  if [ "$mode" = "API_KEY" ]; then
    args+=(-H "X-API-Key: ${API_KEY}")
  else
    args+=(-H "Authorization: Bearer ${TOKEN}")
  fi
  args+=("$url")
  status="$(curl "${args[@]}")"
  printf "(HTTP %s)\n" "$status"
}

assert_status() {
  local want="$1"
  if [ "$status" = "$want" ]; then record_pass; ok "status $want"
  else record_fail; fail "got HTTP $status, want $want"; sed 's/^/  /' "$OUT"; fi
}
assert_jq() {
  local expr="$1" msg="$2"
  if jq -e "$expr" "$OUT" >/dev/null 2>&1; then record_pass; ok "$msg"
  else record_fail; fail "$msg"; echo "Body didn’t match: jq '$expr'"; sed 's/^/  /' "$OUT"; fi
}
step() { sep; bold "$1"; }

# optional DB peeks
psql_show_secrets() {
  local q="
select si.path, sv.version, sv.is_current,
       encode(sv.nonce,'base64') as nonce_b64,
       encode(sv.ciphertext,'base64') as ciphertext_b64,
       sv.alg, (si.path || '|' || sv.version)::text as aad_hint,
       sv.created_at, sv.created_by
from core.secret_items si
join core.secret_versions sv on sv.item_id=si.id
where si.path='${SECRET_PATH}'
order by sv.version;"
  docker compose exec -T postgres bash -lc \
    "gosu postgres psql -d postgres -X -q -x -c \"${q//$'\n'/ }\""
}
psql_show_configs() {
  local q="
select ci.path,
       cv.version,
       cv.is_current,
       cv.data_type,
       encode(cv.checksum,'hex') as checksum_hex,
       cv.value_json,
       cf.file_name,
       cf.file_size,
       cf.content_type,
       cv.created_at,
       cv.created_by
from core.config_items ci
join core.config_versions cv on cv.item_id=ci.id
left join core.config_version_files cf on cf.version_id = cv.id
where ci.path='${CONFIG_PATH}'
order by cv.version;"
  docker compose exec -T postgres bash -lc \
    "gosu postgres psql -d postgres -X -q -x -c \"${q//$'\n'/ }\""
}

# shared test sequence
run_sequence() {
  local mode="$1"

  step "#1 Health"
  echo "==> GET ${BASE}/health"
  run_http "$mode" GET "${BASE}/health"
  assert_status 200
  assert_jq '.status=="ok"' "health OK"

  step "#2 Create secret v1"
  local payload_secret_v1='{"value":{"username":"alice","password":"s3cr3t"}}'
  echo "==> POST ${BASE}/secret/${SECRET_PATH}"
  run_http "$mode" POST "${BASE}/secret/${SECRET_PATH}" "$payload_secret_v1"
  assert_status 201
  assert_jq '.path=="'"$SECRET_PATH"'"' "path matches"
  assert_jq '.version|type=="number"' "version is number"

  step "#3 Read current secret"
  echo "==> GET ${BASE}/secret/${SECRET_PATH}"
  run_http "$mode" GET "${BASE}/secret/${SECRET_PATH}"
  assert_status 200
  assert_jq '.value.username=="alice"' "username=alice"
  assert_jq '.value.password=="s3cr3t"' "password=s3cr3t"

  step "#4 Rotate secret (create v2)"
  local payload_secret_v2='{"value":{"username":"alice","password":"n3wS3cr3t"}}'
  echo "==> POST ${BASE}/secret/${SECRET_PATH}"
  run_http "$mode" POST "${BASE}/secret/${SECRET_PATH}" "$payload_secret_v2"
  assert_status 201
  assert_jq '.value.password=="n3wS3cr3t"' "rotated secret ok"

  step "#5 Read secret version=1"
  echo "==> GET ${BASE}/secret/${SECRET_PATH}?version=1"
  run_http "$mode" GET "${BASE}/secret/${SECRET_PATH}?version=1"
  assert_status 200
  assert_jq '.value.password=="s3cr3t"' "v1 password matches"

  step "#6 Create config v1"
  local payload_cfg='{"value":{"beta_ui":true,"limit":50}}'
  echo "==> POST ${BASE}/config/${CONFIG_PATH}"
  run_http "$mode" POST "${BASE}/config/${CONFIG_PATH}" "$payload_cfg"
  assert_status 201
  assert_jq '.value.beta_ui==true' "config flag set"

  step "#7 Read config current"
  echo "==> GET ${BASE}/config/${CONFIG_PATH}"
  run_http "$mode" GET "${BASE}/config/${CONFIG_PATH}"
  assert_status 200
  assert_jq '.value.limit==50' "config limit=50"

  step "# DB: secret raw rows (${SECRET_PATH})"
  if psql_show_secrets; then record_pass; ok "psql secret query ran"; else record_fail; fail "psql secret query failed"; fi

  step "# DB: config raw rows (${CONFIG_PATH})"
  if psql_show_configs; then record_pass; ok "psql config query ran"; else record_fail; fail "psql config query failed"; fi
}

# run sequences
if [ -n "${API_KEY:-}" ]; then
  bold "Running API_KEY mode"
  run_sequence "API_KEY"
else
  printf "${YLW}! API_KEY not set. Skipping API Key tests.${NC}\n"
fi
if [ "$RUN_BEARER" = "1" ]; then
  bold "Running BEARER mode"
  run_sequence "BEARER"
fi

# summary
sep
if [ "$FAIL" -eq 0 ]; then
  printf "${GREEN}✓ Full smoke finished OK. Passed: %d/%d${NC}\n" "$PASS" "$TOTAL"; exit 0
else
  printf "${RED}✗ Smoke finished with failures. Passed: %d, Failed: %d, Total: %d${NC}\n" "$PASS" "$FAIL" "$TOTAL"; exit 1
fi
