# backend/app/routes/login.py
"""Login endpoint: verifies creds, issues JWT with roles and derived scopes."""

from __future__ import annotations

import logging
import os
from datetime import datetime, timedelta, timezone
from typing import List, Optional

import jwt  # PyJWT
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from psycopg.types.json import Json

from app.db import pool

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["auth"])

# --- ENV / settings ---
JWT_ALG = os.getenv("JWT_ALG", "HS256").strip().upper()
JWT_AUD = os.getenv("JWT_AUDIENCE", "confmgr")
JWT_ISS = os.getenv("ISSUER", "confmgr")
JWT_TTL = int(os.getenv("JWT_TTL_SECONDS", "3600"))

# HS: JWT_SIGNING_KEY (raw or path). RS/ES: JWT_PRIVATE_KEY (PEM or path).
JWT_SIGNING_KEY = os.getenv("JWT_SIGNING_KEY", "")
JWT_PRIVATE_KEY = os.getenv("JWT_PRIVATE_KEY", "")

# Role → scopes map (example; adjust to your policy)
ROLE_SCOPE_MAP = {
    "GLOBAL_ADMIN": ["*"],
    "CONFIG_VIEWER": ["config.read"],
    "CONFIG_ADMIN": ["config.read", "config.write"],
    "SECRET_VIEWER": ["secret.read"],
    "SECRET_ADMIN": ["secret.read", "secret.write"],
    "USER_VIEWER": ["user.read"],
    "USER_ADMIN": ["user.read", "user.write"],
}


# --- Models ---
class LoginIn(BaseModel):
    """Login request payload."""
    username: str
    password: str


class LoginOut(BaseModel):
    """Login response with token and derived capabilities."""
    access_token: str
    token_type: str = "bearer"
    roles: List[str]
    scopes: List[str]


# --- Helpers ---
def _read_key_material(value_or_path: str) -> str:
    """Return PEM/secret from env or file path; raise if missing."""
    if not value_or_path:
        raise ValueError("Missing key material")
    try:
        if os.path.exists(value_or_path):
            with open(value_or_path, "r", encoding="utf-8") as f:
                return f.read()
    except OSError:
        # Fall back to literal string (env already contained PEM/secret)
        pass
    return value_or_path


def _derive_scopes(roles: list[str]) -> list[str]:
    """Union scopes for all roles; '*' wins."""
    scopes: list[str] = []
    for r in roles:
        scopes += ROLE_SCOPE_MAP.get(r, [])
    scopes = sorted(set(scopes))
    return ["*"] if "*" in scopes else scopes


def _issue_jwt(sub: str, roles: list[str], scopes: list[str]) -> str:
    """Create and sign JWT with roles array and space-delimited scope."""
    now = datetime.now(timezone.utc)
    claims = {
        "sub": sub,
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(seconds=JWT_TTL)).timestamp()),
        "roles": roles,
        "scope": " ".join(scopes),
    }

    if JWT_ALG.startswith("HS"):
        key = _read_key_material(JWT_SIGNING_KEY)
    else:
        key = _read_key_material(JWT_PRIVATE_KEY)

    return jwt.encode(claims, key, algorithm=JWT_ALG)


def _check_credentials(username: str, password: str) -> Optional[list[str]]:
    """
    Very basic credential check for demo:
    - admin/admin → GLOBAL_ADMIN
    - config/config → CONFIG_ADMIN
    - otherwise: invalid
    Replace with real DB lookup (bcrypt/argon2) when ready.
    """
    if username == "admin" and password == "admin":
        return ["GLOBAL_ADMIN"]
    if username == "config" and password == "config":
        return ["CONFIG_ADMIN"]
    return None


def _audit(event: str, subject: str, path: str, payload: dict) -> None:
    """Best-effort audit; never raises to the caller."""
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute(
                "select audit.log_event(%s::uuid,%s::text,%s::text,%s::text,%s::jsonb)",
                (
                    "11111111-1111-1111-1111-111111111111",  # system principal
                    subject,
                    event,
                    path,
                    Json(payload),
                ),
            )
            conn.commit()
    except Exception:  # pylint: disable=broad-exception-caught
        logger.debug("audit skipped (best-effort)", exc_info=True)


# --- Route ---
@router.post("/login", response_model=LoginOut)
def login(body: LoginIn) -> LoginOut:
    """Authenticate user and return JWT with roles + scopes."""
    try:
        roles = _check_credentials(body.username, body.password)
        if not roles:
            raise HTTPException(status_code=401, detail="Invalid credentials")

        scopes = _derive_scopes(roles)
        token = _issue_jwt(body.username, roles, scopes)

        _audit("auth.login.success", body.username, "auth/login", {"roles": roles})
        return LoginOut(access_token=token, roles=roles, scopes=scopes)

    except HTTPException:
        # already a proper client error
        _audit("auth.login.fail", body.username, "auth/login", {"reason": "client"})
        raise
    except (jwt.PyJWTError, ValueError, KeyError) as e:
        # expected validation/key errors
        _audit("auth.login.fail", body.username, "auth/login", {"reason": "bad_token"})
        raise HTTPException(status_code=401, detail="Invalid credentials") from e
    except Exception as e:  # unexpected
        logger.exception("Login failed due to server error")
        _audit("auth.login.error", body.username, "auth/login", {"error": e.__class__.__name__})
        raise HTTPException(status_code=500, detail="Authentication service error") from e
