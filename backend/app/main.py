# app/main.py
import os
import re
import json
import hashlib
import uuid

from fastapi import FastAPI, HTTPException, Header, Depends, Query
from fastapi.middleware.cors import CORSMiddleware

from psycopg.rows import dict_row
from psycopg.types.json import Json

from .db import pool
from .auth import require_api_key            # uses API_KEY from env in auth.py
from .crypto import seal, open_sealed
from .models import PutConfigIn, ConfigOut, PutSecretIn, SecretOut

app = FastAPI(title="confmgr-backend")

# ---------- CORS ----------
# Read allowed origins from env; for dev: http://localhost:3000
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "http://localhost:3000")
origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,                # explicit origins (no "*")
    allow_credentials=True,               # allow cookies/auth if needed
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Actor-Id",
        "X-Actor-Subject",
    ],
)

# ---------- Health ----------
@app.get("/health")
def health():
    # Simple DB round-trip to prove connectivity and time source
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("select now()")
        return {"status": "ok", "db_time_utc": cur.fetchone()[0].isoformat()}

@app.get("/healthz")
def healthz():
    # Alias commonly used by probes
    return health()

# ---------- Path normalization / validation ----------
PATH_RE = re.compile(r"^(?:[A-Za-z0-9._-]+)(?:/[A-Za-z0-9._-]+)*$")

def normalize_path(p: str) -> str:
    """
    Enforce a canonical key format:
    - trim whitespace
    - remove trailing slash
    - allow segments [A-Za-z0-9._-], separated by '/'
    This prevents path traversal or accidental duplicates.
    """
    p = p.strip().rstrip("/")
    if not PATH_RE.fullmatch(p):
        raise HTTPException(status_code=400, detail="invalid path")
    return p

# ===================== CONFIG =====================

@app.get(
    "/config/{path:path}",
    response_model=ConfigOut,
    dependencies=[Depends(require_api_key)]
)
def get_config(path: str):
    path = normalize_path(path)
    sql = """
    select cv.version, cv.value_json, cv.created_at
    from core.config_items ci
    join core.config_versions cv on cv.item_id = ci.id
    where ci.path = %s and cv.is_current
    """
    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, (path,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Config not found")
        return {
            "path": path,
            "version": row["version"],
            "value": row["value_json"],
            "created_at": row["created_at"].isoformat(),
        }

@app.post(
    "/config/{path:path}",
    response_model=ConfigOut,
    status_code=201,
    dependencies=[Depends(require_api_key)]
)
def put_config(
    path: str,
    payload: PutConfigIn,
    x_actor_id: str | None = Header(default=None, alias="X-Actor-Id"),
    x_actor_subject: str | None = Header(default=None, alias="X-Actor-Subject"),
):
    path = normalize_path(path)
    value = payload.value

    # Canonical JSON for deterministic checksum
    value_canon = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    checksum = hashlib.sha256(value_canon).digest()
    created_by = uuid.UUID(x_actor_id) if x_actor_id else uuid.UUID("00000000-0000-0000-0000-000000000001")

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Ensure item exists
        cur.execute(
            "insert into core.config_items(path, created_by) values (%s, %s) on conflict(path) do nothing",
            (path, created_by),
        )

        # Optional idempotency: if current checksum matches, short-circuit
        cur.execute("""
            select cv.version, cv.checksum, cv.created_at
            from core.config_items ci
            join core.config_versions cv on cv.item_id = ci.id
            where ci.path = %s and cv.is_current
        """, (path,))
        current = cur.fetchone()
        if current and current["checksum"] == checksum:
            return {
                "path": path,
                "version": current["version"],
                "value": value,
                "created_at": current["created_at"].isoformat(),
            }

        # Insert new version; DB trigger or default increments version when 'null'
        cur.execute("""
            insert into core.config_versions(item_id, version, is_current, value_json, checksum, created_by)
            select id, null, true, %s::jsonb, %s::bytea, %s
            from core.config_items where path = %s
            returning version, created_at
        """, (Json(value), checksum, created_by, path))
        row = cur.fetchone()

        # Audit log
        cur.execute("""
            select audit.log_event(%s::uuid, %s::text, %s::text, %s::text, %s::jsonb)
        """, (
            created_by,
            (x_actor_subject or "api_key"),
            "config.put",
            path,
            Json({"version": row["version"]}),
        ))

        conn.commit()

    return {"path": path, "version": row["version"], "value": value, "created_at": row["created_at"].isoformat()}

# ===================== SECRETS (AES-GCM at rest) =====================

@app.get(
    "/secret/{path:path}",
    response_model=SecretOut,
    dependencies=[Depends(require_api_key)]
)
def get_secret(
    path: str,
    version: int | None = Query(default=None, description="Optional explicit version"),
):
    path = normalize_path(path)
    # Either fetch explicit version, or the current one
    if version is None:
        sql = """
        select sv.version, sv.ciphertext, sv.nonce, sv.alg, sv.created_at
        from core.secret_items si
        join core.secret_versions sv on sv.item_id = si.id
        where si.path = %s and sv.is_current
        """
        params = (path,)
    else:
        sql = """
        select sv.version, sv.ciphertext, sv.nonce, sv.alg, sv.created_at
        from core.secret_items si
        join core.secret_versions sv on sv.item_id = si.id
        where si.path = %s and sv.version = %s
        """
        params = (path, version)

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Secret not found")
        if row["alg"] != "AES256-GCM":
            raise HTTPException(500, "Unsupported algorithm")

        # AAD binds ciphertext to (path|version)
        aad = f"{path}|{row['version']}".encode()
        plaintext = open_sealed(row["nonce"], row["ciphertext"], aad=aad)
        value = json.loads(plaintext.decode())

        return {
            "path": path,
            "version": row["version"],
            "value": value,
            "created_at": row["created_at"].isoformat(),
        }

@app.post(
    "/secret/{path:path}",
    response_model=SecretOut,
    status_code=201,
    dependencies=[Depends(require_api_key)]
)
def put_secret(
    path: str,
    payload: PutSecretIn,
    x_actor_id: str | None = Header(default=None, alias="X-Actor-Id"),
    x_actor_subject: str | None = Header(default=None, alias="X-Actor-Subject"),
):
    path = normalize_path(path)
    value = payload.value
    created_by = uuid.UUID(x_actor_id) if x_actor_id else uuid.UUID("00000000-0000-0000-0000-000000000001")

    # Canonical plaintext for deterministic crypto
    plaintext = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # 1) Ensure parent item exists
        cur.execute("""
            insert into core.secret_items(path, created_by)
            values (%s, %s)
            on conflict(path) do nothing
        """, (path, created_by))

        # 2) Lock the parent row to serialize writers (no FOR UPDATE on aggregates)
        cur.execute("select id from core.secret_items where path = %s for update", (path,))
        item = cur.fetchone()
        if not item:
            raise HTTPException(500, "Secret item not created")
        item_id = item["id"]

        # 3) Compute next version under the parent lock
        cur.execute("select coalesce(max(version), 0) as mv from core.secret_versions where item_id = %s", (item_id,))
        next_ver = cur.fetchone()["mv"] + 1

        # 4) Encrypt with AAD binding ciphertext to (path|version)
        aad = f"{path}|{next_ver}".encode()
        nonce, ct = seal(plaintext, aad=aad)

        # 5) Flip current and insert the new current version atomically
        cur.execute("update core.secret_versions set is_current = false where item_id = %s and is_current", (item_id,))
        cur.execute("""
            insert into core.secret_versions(item_id, version, is_current, ciphertext, nonce, alg, created_by)
            values (%s, %s, true, %s::bytea, %s::bytea, 'AES256-GCM', %s)
            returning version, created_at
        """, (item_id, next_ver, ct, nonce, created_by))
        ver_row = cur.fetchone()

        # Audit log
        cur.execute("""
            select audit.log_event(%s::uuid, %s::text, %s::text, %s::text, %s::jsonb)
        """, (
            created_by,
            (x_actor_subject or "api_key"),
            "secret.put",
            path,
            Json({"version": ver_row["version"]}),
        ))

        conn.commit()

    return {
        "path": path,
        "version": ver_row["version"],
        "value": value,
        "created_at": ver_row["created_at"].isoformat(),
    }
# ===================== END =====================
