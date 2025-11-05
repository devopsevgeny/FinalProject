# backend/app/security/auth.py
"""Authentication helpers: API key / Bearer JWT validators."""
import os
import logging
import re
from dataclasses import dataclass
from typing import Optional, Any, Dict, NoReturn
from uuid import UUID

from fastapi import Header, HTTPException
import jwt  # PyJWT

logger = logging.getLogger(__name__)

AUTH_TYPE = os.getenv("AUTH_TYPE", "API_KEY").strip().upper()
API_KEY = os.getenv("API_KEY", "")

JWT_ALG = os.getenv("JWT_ALG", "HS256").strip().upper()
JWT_SIGNING_KEY = os.getenv("JWT_SIGNING_KEY", "")
JWT_PUBLIC_KEY = os.getenv("JWT_PUBLIC_KEY", "")
JWT_PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY", "")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "confmgr")
ISSUER = os.getenv("ISSUER", "")

_DEFAULT_SYSTEM_PRINCIPAL_ID = "00000000-0000-0000-0000-000000000001"
SYSTEM_PRINCIPAL_ID = os.getenv("SYSTEM_PRINCIPAL_ID", _DEFAULT_SYSTEM_PRINCIPAL_ID)


@dataclass
class AuthPrincipal:
    """Represents an authenticated principal."""
    id: str
    subject: Optional[str] = None
    issuer: Optional[str] = None
    roles: Optional[list[str]] = None      # groups / RBAC roles
    scopes: Optional[list[str]] = None     # permissions (derived from 'scope' claims)


def _unauth(detail: str) -> NoReturn:
    """Raise 401 with a generic message, log internal detail."""
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
    """Stable unique list."""
    out: list[str] = []
    for x in xs:
        if x and x not in out:
            out.append(x)
    return out


def _read_key_material(value_or_path: str | None) -> str:
    """Return key contents whether provided directly or via file path."""
    if not value_or_path:
        return ""
    try:
        if os.path.exists(value_or_path):
            with open(value_or_path, "r", encoding="utf-8") as handle:
                return handle.read()
    except OSError:
        # Fall back to treating the value as inline key material.
        pass
    return value_or_path


def _verification_key() -> str:
    """Resolve key material appropriate for the configured JWT algorithm."""
    alg = JWT_ALG or "HS256"
    if alg.startswith("HS"):
        key = _read_key_material(JWT_SIGNING_KEY)
        if not key:
            _unauth("JWT_SIGNING_KEY not configured")
        return key

    public_key = _read_key_material(JWT_PUBLIC_KEY)
    private_key = _read_key_material(JWT_PRIVATE_KEY)
    key = public_key or private_key
    if not key:
        _unauth("JWT_PUBLIC_KEY or JWT_PRIVATE_KEY not configured")
    return key


def _extract_roles(payload: Dict[str, Any]) -> list[str]:
    """Extract roles/groups only (do not mix with 'scope')."""
    roles: list[str] = []
    roles += _to_list(payload.get("roles"))        # canonical
    roles += _to_list(payload.get("groups"))       # alternates
    realm = payload.get("realm_access") or {}      # keycloak
    if isinstance(realm, dict):
        roles += _to_list(realm.get("roles"))
    res = payload.get("resource_access") or {}     # keycloak resource roles
    if isinstance(res, dict):
        for v in res.values():
            if isinstance(v, dict):
                roles += _to_list(v.get("roles"))
    return _unique(roles)


def _extract_scopes(payload: Dict[str, Any]) -> list[str]:
    """Extract OAuth2-like permissions from 'scope'-style claims only."""
    scopes: list[str] = []
    scopes += _to_list(payload.get("scope"))   # standard space-delimited
    scopes += _to_list(payload.get("scopes"))  # sometimes array/alt
    scopes += _to_list(payload.get("scp"))     # Azure AD
    return _unique(scopes)


def _coerce_uuid(value: str | None) -> str | None:
    """Return normalized UUID string or None when input is falsy/invalid."""
    if not value:
        return None
    try:
        return str(UUID(str(value)))
    except (ValueError, TypeError):
        return None


def _require_bearer(authorization: str | None = Header(default=None, alias="Authorization")) -> AuthPrincipal:
    """Validate a Bearer JWT and build AuthPrincipal with separate roles/scopes."""
    if not authorization:
        _unauth("Missing Authorization header")
    parts = authorization.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        _unauth("Malformed Authorization header")

    token = parts[1]

    # Only signature/claims decoding inside try; a single return at the end.
    try:
        payload = jwt.decode(
            token,
            _verification_key(),
            algorithms=[JWT_ALG],
            audience=JWT_AUDIENCE,
            issuer=ISSUER,
            leeway=30,
            options={"require": ["exp", "iat", "sub"]},
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

    roles = _extract_roles(payload)
    scopes = _extract_scopes(payload)
    principal = AuthPrincipal(
        id=str(payload.get("sub") or "bearer"),
        subject=payload.get("sub"),
        issuer=payload.get("iss"),
        roles=roles or [],
        scopes=scopes or [],
    )
    return principal  # single explicit return fixes R1710


# Public aliases for FastAPI dependencies
require_api_key = _require_api_key
require_bearer = _require_bearer


def resolve_created_by(principal: AuthPrincipal | None, x_actor_id: str | None) -> str:
    """Resolve the created_by ID from principal or X-Actor-Id header."""
    if x_actor_id:
        normalized = _coerce_uuid(x_actor_id)
        if not normalized:
            raise HTTPException(status_code=400, detail="X-Actor-Id must be a valid UUID")
        return normalized

    if principal:
        normalized = _coerce_uuid(principal.id)
        if normalized:
            return normalized

    fallback = _coerce_uuid(SYSTEM_PRINCIPAL_ID)
    if fallback:
        return fallback

    logger.error("SYSTEM_PRINCIPAL_ID is not a valid UUID")
    raise HTTPException(status_code=500, detail="Server misconfiguration: SYSTEM_PRINCIPAL_ID invalid")


__all__ = ["require_api_key", "require_bearer", "AuthPrincipal", "resolve_created_by", "SYSTEM_PRINCIPAL_ID"]
