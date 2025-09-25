import os
import logging
from dataclasses import dataclass
from typing import Optional
from fastapi import Header, HTTPException

import jwt  # PyJWT

logger = logging.getLogger(__name__)

AUTH_TYPE = os.getenv("AUTH_TYPE", "API_KEY").strip().upper()

# API Key
API_KEY = os.getenv("API_KEY", "")

# JWT params
JWT_ALG = os.getenv("JWT_ALG", "HS256")
JWT_SIGNING_KEY = os.getenv("JWT_SIGNING_KEY", "")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "confmgr")
ISSUER = os.getenv("ISSUER", "")

@dataclass
class AuthPrincipal:
    """Represents an authenticated principal"""
    id: str
    subject: Optional[str] = None
    issuer: Optional[str] = None
    scopes: Optional[list[str]] = None

def _unauth(detail: str):
    logger.warning("Auth failed: %s", detail)
    raise HTTPException(status_code=401, detail="Unauthorized")

def _require_api_key(x_api_key: str | None = Header(default=None, alias="X-API-Key")) -> AuthPrincipal:
    if not API_KEY:
        _unauth("API_KEY not configured")
    if not x_api_key:
        _unauth("Missing X-API-Key header")
    if x_api_key != API_KEY:
        _unauth("Invalid API key")
    return AuthPrincipal(id="api-key")

def _require_bearer(authorization: str | None = Header(default=None)) -> AuthPrincipal:
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
        return AuthPrincipal(
            id=payload["sub"],
            subject=payload.get("sub"),
            issuer=payload.get("iss"),
            scopes=payload.get("scope", "").split() if "scope" in payload else None
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
    """Resolve the created_by ID from principal or X-Actor-Id header"""
    if x_actor_id:
        return x_actor_id
    return principal.id if principal else "system"

# Export the public interface
require_api_key = _require_api_key
require_bearer = _require_bearer

__all__ = ["require_api_key", "require_bearer", "AuthPrincipal", "resolve_created_by"]