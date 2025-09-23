# app/auth.py
import os, uuid, json, time, hmac, hashlib, base64
from dataclasses import dataclass
from fastapi import Header, HTTPException

# ---- JWT config (HS256) ----
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_KEY = os.getenv("JWT_SIGNING_KEY", "")
JWT_ISS = os.getenv("ISSUER", "confmgr")
JWT_AUD = os.getenv("JWT_AUDIENCE", "confmgr")

# ---- API key (dev/temporary) ----
API_KEY = os.getenv("API_KEY", "")

@dataclass
class AuthPrincipal:
    id: str | None = None       # sub
    subject: str | None = None  # preferred_username/name/email
    issuer: str | None = None   # iss
    scopes: list[str] | None = None

SYSTEM_PRINCIPAL = uuid.UUID(os.getenv(
    "SYSTEM_PRINCIPAL_ID",
    "00000000-0000-0000-0000-000000000001"
))

# --- helpers ---
def _b64url_decode(seg: str) -> bytes:
    pad = '=' * ((4 - len(seg) % 4) % 4)
    return base64.urlsafe_b64decode(seg + pad)

def _verify_hs256_jwt(token: str) -> AuthPrincipal:
    try:
        head_b64, payload_b64, sig_b64 = token.split('.', 2)
        header = json.loads(_b64url_decode(head_b64))
        payload = json.loads(_b64url_decode(payload_b64))
        sig = _b64url_decode(sig_b64)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token format")

    if header.get("alg") != "HS256" or JWT_ALG != "HS256":
        raise HTTPException(status_code=401, detail="Unsupported JWT alg")

    if not JWT_KEY:
        raise HTTPException(status_code=500, detail="JWT key not configured")

    signing = f"{head_b64}.{payload_b64}".encode()
    expected = hmac.new(JWT_KEY.encode(), signing, hashlib.sha256).digest()
    if not hmac.compare_digest(expected, sig):
        raise HTTPException(status_code=401, detail="Bad token signature")

    now = int(time.time())
    iss = payload.get("iss")
    aud = payload.get("aud")
    exp = payload.get("exp")
    nbf = payload.get("nbf", 0)

    if JWT_ISS and iss != JWT_ISS:
        raise HTTPException(status_code=401, detail="Bad token issuer")
    if JWT_AUD and aud != JWT_AUD:
        raise HTTPException(status_code=401, detail="Bad token audience")
    if not isinstance(exp, int) or exp <= now:
        raise HTTPException(status_code=401, detail="Token expired")
    if isinstance(nbf, int) and nbf > now:
        raise HTTPException(status_code=401, detail="Token not yet valid")

    sub = payload.get("sub")
    subj = payload.get("preferred_username") or payload.get("name") or payload.get("email")
    scopes = payload.get("scope")
    if isinstance(scopes, str):
        scopes = scopes.split()

    return AuthPrincipal(id=sub, subject=subj, issuer=iss, scopes=scopes)

# --- API-Key only guard (dev) ---
def require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> AuthPrincipal | None:
    if not API_KEY or x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized")
    return None  # no identity in API-key mode

# --- Bearer-only guard (prod) ---
def require_bearer(authorization: str | None = Header(default=None, alias="Authorization")) -> AuthPrincipal:
    if not authorization:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    scheme, _, token = authorization.partition(' ')
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status_code=401, detail="Invalid Authorization scheme")
    return _verify_hs256_jwt(token)

def resolve_created_by(principal: AuthPrincipal | None, x_actor_id: str | None) -> uuid.UUID:
    # Prefer JWT 'sub'
    if principal and principal.id:
        try:
            return uuid.UUID(principal.id)
        except ValueError:
            pass
    # Fallback to header
    if x_actor_id:
        try:
            return uuid.UUID(x_actor_id)
        except ValueError:
            raise HTTPException(status_code=400, detail="X-Actor-Id must be a UUID")
    # Final fallback
    return SYSTEM_PRINCIPAL
