# app/security/auth.py
import os
import logging
import re
from dataclasses import dataclass
from typing import Optional, Any, Dict
from fastapi import Header, HTTPException
import jwt  # PyJWT

logger = logging.getLogger(__name__)

AUTH_TYPE = os.getenv("AUTH_TYPE", "API_KEY").strip().upper()
API_KEY   = os.getenv("API_KEY", "")

JWT_ALG         = os.getenv("JWT_ALG", "HS256")
JWT_SIGNING_KEY = os.getenv("JWT_SIGNING_KEY", "")
JWT_AUDIENCE    = os.getenv("JWT_AUDIENCE", "confmgr")
ISSUER          = os.getenv("ISSUER", "")

@dataclass
class AuthPrincipal:
    """Represents an authenticated principal."""
    id: str
    subject: Optional[str] = None
    issuer: Optional[str] = None
    roles: Optional[list[str]] = None     # groups / RBAC roles
    scopes: Optional[list[str]] = None    # permissions (derived from 'scope' claims)

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
    # For API key we don't assign roles/scopes by default
    return AuthPrincipal(id="api-key", subject="api-key", issuer="local", roles=[], scopes=[])

_SPLIT_RE = re.compile(r"[,\s]+")

def _to_list(v: Any) -> list[str]:
    """Coerce common representations to list[str]."""
    if v is None:
        return []
    if isinstance(v, (list, tuple)):
        return [str(x) for x in v if str(x).strip()]
    if isinstance(v, str):
        s = v.strip()
        if s.startswith("{") and s.endswith("}"):
            inner = s[1:-1]
            items = [p.strip().strip('"') for p in inner.split(",")]
            return [i for i in items if i]
        return [p for p in _SPLIT_RE.split(s) if p]
    return [str(v)] if str(v).strip() else []

def _unique(xs: list[str]) -> list[str]:
    out: list[str] = []
    for x in xs:
        if x and x not in out:
            out.append(x)
    return out

def _extract_roles(payload: Dict[str, Any]) -> list[str]:
    """Extract roles/groups only (do not mix with 'scope')."""
    roles: list[str] = []
    # Our canonical claim
    roles += _to_list(payload.get("roles"))
    # Common alternates
    roles += _to_list(payload.get("groups"))
    # Keycloak styles
    realm = payload.get("realm_access") or {}
    if isinstance(realm, dict):
        roles += _to_list(realm.get("roles"))
    res = payload.get("resource_access") or {}
    if isinstance(res, dict):
        for v in res.values():
            if isinstance(v, dict):
                roles += _to_list(v.get("roles"))
    return _unique(roles)

def _extract_scopes(payload: Dict[str, Any]) -> list[str]:
    """Extract OAuth2-like permissions from 'scope'-style claims only."""
    scopes: list[str] = []
    # Standard OAuth2 (space-delimited string)
    scopes += _to_list(payload.get("scope"))
    # Sometimes providers put array or alt claim name
    scopes += _to_list(payload.get("scopes"))
    # Azure AD often uses 'scp'
    scopes += _to_list(payload.get("scp"))
    return _unique(scopes)

def _require_bearer(authorization: str | None = Header(default=None)) -> AuthPrincipal:
    """Validate a Bearer JWT and build AuthPrincipal with separate roles/scopes."""
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
        roles  = _extract_roles(payload)
        scopes = _extract_scopes(payload)
        return AuthPrincipal(
            id=payload["sub"],
            subject=payload.get("sub"),
            issuer=payload.get("iss"),
            roles=roles or [],
            scopes=scopes or [],
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

require_api_key = _require_api_key
require_bearer  = _require_bearer

def resolve_created_by(principal: AuthPrincipal, x_actor_id: str | None) -> str:
    """Resolve the created_by ID from principal or X-Actor-Id header."""
    if x_actor_id:
        return x_actor_id
    return principal.id if principal else "system"

__all__ = ["require_api_key", "require_bearer", "AuthPrincipal", "resolve_created_by"]
