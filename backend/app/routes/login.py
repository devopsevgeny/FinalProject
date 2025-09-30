# app/routes/login.py
import os, datetime as dt, jwt
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from psycopg.rows import dict_row
from app.db import pool

router = APIRouter(prefix="/auth", tags=["auth"])

JWT_ALG   = os.getenv("JWT_ALG", "HS256")
JWT_ISS   = os.getenv("ISSUER", "confmgr")
JWT_AUD   = os.getenv("JWT_AUDIENCE", "confmgr")
JWT_KEY   = os.getenv("JWT_SIGNING_KEY", "devsecret")
JWT_TTL_S = int(os.getenv("JWT_EXP_DELTA_SECONDS", "3600"))

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
    now = dt.datetime.now(dt.timezone.utc)
    exp = now + dt.timedelta(seconds=JWT_TTL_S)
    payload = {
        "sub": user_id,
        "username": username,
        "email": email,
        "roles": roles,             # массив
        "scopes": roles,            # массив (синоним)
        "scope": " ".join(roles),   # строка (OAuth2-совместимо)
        "iss": JWT_ISS, "aud": JWT_AUD,
        "iat": int(now.timestamp()), "exp": int(exp.timestamp()),
    }
    return jwt.encode(payload, JWT_KEY, algorithm=JWT_ALG)

@router.post("/login")
def login(body: LoginIn):
    try:
        with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
            cur.execute(SQL_LOGIN, (body.username, body.password))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=401, detail="Invalid credentials")

            # нормализуем роли на всякий случай
            raw_roles = row["roles"]
            if raw_roles is None:
                roles = []
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

            cur.execute("UPDATE core.users SET last_login = now() WHERE id = %s", (user_id,))
            conn.commit()

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
        raise HTTPException(status_code=500, detail=f"Auth error: {e}")
