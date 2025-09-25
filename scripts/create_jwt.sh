# Generate a JWT in the backend container
TOKEN=$(docker compose exec -T backend python - <<'PY'
import os, time, json, base64, hmac, hashlib, uuid
key = os.environ.get("JWT_SIGNING_KEY", "changeme").encode()
iss = os.environ.get("ISSUER", "confmgr-local")
aud = os.environ.get("JWT_AUDIENCE", "confmgr")
exp_delta = int(os.environ.get("JWT_EXP_DELTA_SECONDS", "3600"))
now = int(time.time())

payload = {
  "iss": iss,
  "sub": str(uuid.uuid4()),   # or fix to a known principal UUID
  "aud": aud,
  "iat": now,
  "nbf": now - 10,
  "exp": now + exp_delta,
  "scope": "confmgr:rw",
  "name": "evgeny"
}

def b64url(x: bytes) -> bytes:
    return base64.urlsafe_b64encode(x).rstrip(b'=')

header = {"alg": "HS256", "typ": "JWT"}
segments = [
    b64url(json.dumps(header, separators=(',',':')).encode()),
    b64url(json.dumps(payload, separators=(',',':')).encode()),
]
signing = b'.'.join(segments)
sig = b64url(hmac.new(key, signing, hashlib.sha256).digest())
print((signing + b'.' + sig).decode())
PY
)

echo "JWT: $TOKEN"
# Note: 'export TOKEN' will only persist in the parent shell if this script is sourced (e.g., 'source create_jwt.sh' or '. create_jwt.sh')
export TOKEN