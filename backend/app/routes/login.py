# app/routes/login.py
import os
import datetime as dt
import jwt
import logging
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
from psycopg.rows import dict_row
from psycopg.types.json import Json
from app.db import pool

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# JWT config
JWT_ALG   = os.getenv("JWT_ALG", "HS256")
JWT_ISS   = os.getenv("ISSUER", "confmgr")
JWT_AUD   = os.getenv("JWT_AUDIENCE", "confmgr")
JWT_KEY   = os.getenv("JWT_SIGNING_KEY", "devsecret")
JWT_TTL_S = int(os.getenv("JWT_EXP_DELTA_SECONDS", "3600"))

# System actor id for unauthenticated audit events (failed/error)
SYSTEM_PRINCIPAL_ID = os.getenv(
    "SYSTEM_PRINCIPAL_ID",
    "00000000-0000-0000-0000-000000000001"
)

# RBAC -> OAuth2-like scopes mapping (derived permissions)
ROLE_TO_SCOPES = {
    "GLOBAL_ADMIN": ["config.read","config.write","secret.read","secret.write","user.read","user.write"],
    "CONFIG_ADMIN": ["config.read","config.write"],
    "CONFIG_VIEWER":["config.read"],
    "SECRET_ADMIN": ["secret.read","secret.write"],
    "SECRET_VIEWER":["secret.read"],
    "USER_ADMIN":   ["user.read","user.write"],
    "USER_VIEWER":  ["user.read"],
}

def scopes_from_roles(roles: list[str]) -> str:
    """Map roles to a space-delimited scope string (least-privilege friendly)."""
    perms: list[str] = []
    for r in roles:
        for p in ROLE_TO_SCOPES.get(r, []):
            if p not in perms:
                perms.append(p)
    return " ".join(perms)

class LoginIn(BaseModel):
    username: str
    password: str

SQL_LOGIN = """
SELECT
  u.id::text,
  u.username,
  u.email,
  COALESCE(
    ARRAY_AGG(DISTINCT r.name ORDER BY r.name)
      FILTER (WHERE r.name IS NOT NULL),
    ARRAY[]::core.role_type[]
  ) AS roles
FROM core.users u
LEFT JOIN core.user_roles ur ON ur.user_id = u.id
LEFT JOIN core.roles r ON r.id = ur.role_id
WHERE u.username = %s
  AND u.is_active = true
  AND u.password_hash = digest(%s, 'sha256')
GROUP BY u.id, u.username, u.email
"""

def mint_jwt(user_id: str, username: str, email: str, roles: list[str]) -> str:
    """Build and sign a short-lived JWT used by the frontend as a Bearer token."""
    now = dt.datetime.now(dt.timezone.utc)
    exp = now + dt.timedelta(seconds=JWT_TTL_S)
    payload = {
        "sub": user_id,
        "username": username,
        "email": email,
        "roles": roles,                       # canonical RBAC claim
        "scope": scopes_from_roles(roles),    # derived OAuth2-like permissions
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "iat": int(now.timestamp()),
        "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, JWT_KEY, algorithm=JWT_ALG)

@router.post("/login")
def login(body: LoginIn, request: Request):
    """Authenticate user by username/password, issue JWT, and audit the attempt."""
    client_ip = request.headers.get("x-forwarded-for") or (request.client.host if request.client else None)
    user_agent = request.headers.get("user-agent")

    try:
        with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            # Verify credentials and collect roles
            cur.execute(SQL_LOGIN, (body.username, body.password))
            row = cur.fetchone()
            if not row:
                # Audit failed login (wrong credentials)
                try:
                    cur.execute(
                        "select audit.log_event(%s::uuid,%s::text,%s::text,%s::text,%s::jsonb)",
                        (
                            SYSTEM_PRINCIPAL_ID,
                            body.username,
                            "auth.login.failed",
                            "auth/login",
                            Json({"client_ip": client_ip, "user_agent": user_agent}),
                        ),
                    )
                    conn.commit()
                except Exception:
                    conn.rollback()
                raise HTTPException(status_code=401, detail="Invalid credentials")

            # Normalize roles to a plain list[str] (defensive)
            raw_roles = row["roles"]
            if raw_roles is None:
                roles: list[str] = []
            elif isinstance(raw_roles, (list, tuple)):
                roles = list(raw_roles)
            elif isinstance(raw_roles, str):
                s = raw_roles.strip()
                roles = [] if s == "{}" else [p.strip().strip('"') for p in s.strip("{}").split(",") if p.strip()]
            else:
                roles = []

            user_id  = row["id"]
            username = row["username"]
            email    = row["email"]

            # Best-effort last_login update
            try:
                cur.execute("UPDATE core.users SET last_login = now() WHERE id = %s", (user_id,))
            except Exception:
                conn.rollback()  # do not fail auth on this

            # Audit success
            try:
                cur.execute(
                    "select audit.log_event(%s::uuid,%s::text,%s::text,%s::text,%s::jsonb)",
                    (
                        user_id,
                        username or body.username,
                        "auth.login.success",
                        "auth/login",
                        Json({"client_ip": client_ip, "user_agent": user_agent, "roles": roles}),
                    ),
                )
                conn.commit()
            except Exception:
                conn.rollback()

            token = mint_jwt(user_id, username, email, roles)
            return {
                "access_token": token,
                "token_type": "bearer",
                "user": {
                    "id": user_id,
                    "username": username,
                    "email": email,
                    "roles": roles
                }
            }

    except HTTPException:
        raise
    except Exception as e:
        # Audit unexpected error; do not leak details to the client
        logger.exception("Login failed due to server error")
        try:
            with pool.connection() as conn, conn.cursor() as cur:
                cur.execute(
                    "select audit.log_event(%s::uuid,%s::text,%s::text,%s::text,%s::jsonb)",
                    (
                        SYSTEM_PRINCIPAL_ID,
                        body.username,
                        "auth.login.error",
                        "auth/login",
                        Json({"error": str(e), "client_ip": client_ip, "user_agent": user_agent}),
                    ),
                )
                conn.commit()
        except Exception:
            pass
        raise HTTPException(status_code=500, detail="Authentication service error")
