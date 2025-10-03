# app/security/auth.py
import os
import logging
import re
from dataclasses import dataclass
from typing import Optional, Any, Dict
from fastapi import Header, HTTPException
import jwt  # PyJWT

logger = logging.getLogger(__name__)

# API Key vs Bearer is chosen by app at startup via AUTH_TYPE
AUTH_TYPE = os.getenv("AUTH_TYPE", "API_KEY").strip().upper()

# API Key
API_KEY = os.getenv("API_KEY", "")

# JWT params
JWT_ALG        = os.getenv("JWT_ALG", "HS256")
JWT_SIGNING_KEY= os.getenv("JWT_SIGNING_KEY", "")
JWT_AUDIENCE   = os.getenv("JWT_AUDIENCE", "confmgr")
ISSUER         = os.getenv("ISSUER", "")

@dataclass
class AuthPrincipal:
    """Represents an authenticated principal."""
    id: str
    subject: Optional[str] = None
    issuer: Optional[str] = None
    scopes: Optional[list[str]] = None  # normalized roles/permissions

def _unauth(detail: str):
    logger.warning("Auth failed: %s", detail)
    raise HTTPException(status_code=401, detail="Unauthorized")

def _require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> AuthPrincipal:
    """Simple header-based API key auth."""
    if not API_KEY:
        _unauth("API_KEY not configured")
    if not x_api_key:
        _unauth("Missing X-API-Key header")
    if x_api_key != API_KEY:
        _unauth("Invalid API key")
    return AuthPrincipal(id="api-key", subject="api-key", issuer="local", scopes=[])

# ---------- helpers to extract roles/scopes from arbitrary JWT payload ----------

_SPLIT_RE = re.compile(r"[,\s]+")

def _to_list(v: Any) -> list[str]:
    """Coerce common representations to list[str]."""
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if str(x).strip()]
    if isinstance(v, str):
        s = v.strip()
        # Postgres text array form: {"A","B"} or {A,B}
        if s.startswith("{") and s.endswith("}"):
            inner = s[1:-1]
            items = [p.strip().strip('"') for p in inner.split(",")]
            return [i for i in items if i]
        # space/comma separated
        return [p for p in _SPLIT_RE.split(s) if p]
    # fallback
    return [str(v)] if str(v).strip() else []

def _extract_scopes(payload: Dict[str, Any]) -> list[str]:
    """
    Normalize roles/scopes from various claims into a unique list[str].
    Priority: roles (our canonical), then scopes/scope/groups, then common IdP shapes.
    """
    out: list[str] = []
    def add(xs: list[str]):
        nonlocal out
        for x in xs:
            if x and x not in out:
                out.append(x)

    # Our canonical claim
    add(_to_list(payload.get("roles")))
    # Alternatives we may see
    add(_to_list(payload.get("scopes")))
    add(_to_list(payload.get("scope")))
    add(_to_list(payload.get("groups")))

    # Keycloak-style
    realm = payload.get("realm_access") or {}
    if isinstance(realm, dict):
        add(_to_list(realm.get("roles")))

    res = payload.get("resource_access") or {}
    if isinstance(res, dict):
        for v in res.values():
            if isinstance(v, dict):
                add(_to_list(v.get("roles")))

    return out

def _require_bearer(authorization: str | None = Header(default=None)) -> AuthPrincipal:
    """Validate a Bearer JWT and build AuthPrincipal with normalized scopes."""
    if not authorization:
        _unauth("Missing Authorization header")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        _unauth("Malformed Authorization header")

    token = parts[1]
    try:
        payload = jwt.decode(
            token,
            JWT_SIGNING_KEY,
            algorithms=[JWT_ALG],
            audience=JWT_AUDIENCE,
            issuer=ISSUER,
            leeway=30,
            options={"require": ["exp", "iat", "sub"]},
        )
        scopes = _extract_scopes(payload)
        return AuthPrincipal(
            id=payload["sub"],
            subject=payload.get("sub"),
            issuer=payload.get("iss"),
            scopes=scopes or [],  # never None to avoid nulls in /whoami
        )
    except jwt.ExpiredSignatureError:
        _unauth("Token expired")
    except jwt.InvalidAudienceError:
        _unauth("Bad audience")
    except jwt.InvalidIssuerError:
        _unauth("Bad issuer")
    except jwt.InvalidSignatureError:
        _unauth("Bad signature")
    except jwt.PyJWTError as e:
        _unauth(f"JWT error: {e}")

def resolve_created_by(principal: AuthPrincipal, x_actor_id: str | None) -> str:
    """Resolve the created_by ID from principal or X-Actor-Id header."""
    if x_actor_id:
        return x_actor_id
    return principal.id if principal else "system"

# Public interface
require_api_key = _require_api_key
require_bearer  = _require_bearer

__all__ = ["require_api_key", "require_bearer", "AuthPrincipal", "resolve_created_by"]
