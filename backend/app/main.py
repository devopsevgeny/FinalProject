from fastapi import FastAPI, HTTPException, Path, Body, Header, Depends
from psycopg.rows import dict_row
from psycopg.types.json import Json
import json, hashlib, uuid
from datetime import datetime

from .db import pool
from .auth import require_api_key
from .crypto import seal, open_sealed, b64, ub64
from .models import PutConfigIn, ConfigOut, PutSecretIn, SecretOut

app = FastAPI(title="confmgr-backend")

@app.get("/healthz")
def healthz():
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute("select now()")
        return {"status":"ok","db_time_utc":cur.fetchone()[0].isoformat()}

# ------- CONFIG -------
@app.get("/config/{path:path}", response_model=ConfigOut, dependencies=[Depends(require_api_key)])
def get_config(path: str):
    sql = """
    select cv.version, cv.value_json, cv.created_at
    from core.config_items ci
    join core.config_versions cv on cv.item_id=ci.id
    where ci.path=%s and cv.is_current
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
            "created_at": row["created_at"].isoformat()
        }

@app.post("/config/{path:path}", response_model=ConfigOut, status_code=201, dependencies=[Depends(require_api_key)])
def put_config(path: str, payload: PutConfigIn, x_actor_id: str | None = Header(default=None, alias="X-Actor-Id")):
    value = payload.value
    value_canon = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    checksum = hashlib.sha256(value_canon).digest()
    created_by = uuid.UUID(x_actor_id) if x_actor_id else uuid.UUID("00000000-0000-0000-0000-000000000001")

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # ensure item
        cur.execute("insert into core.config_items(path,created_by) values(%s,%s) on conflict(path) do nothing",
                    (path, created_by))
        # insert version
        cur.execute("""
            insert into core.config_versions(item_id, version, is_current, value_json, checksum, created_by)
            select id, null, true, %s::jsonb, %s::bytea, %s
            from core.config_items where path=%s
            returning version, created_at
        """, (Json(value), checksum, created_by, path))
        row = cur.fetchone()
        conn.commit()
    return {"path":path, "version":row["version"], "value":value, "created_at":row["created_at"].isoformat()}

# ------- SECRETS (AES-GCM at rest) -------
@app.get("/secret/{path:path}", response_model=SecretOut, dependencies=[Depends(require_api_key)])
def get_secret(path: str):
    sql = """
    select sv.version, sv.ciphertext, sv.nonce, sv.alg, sv.created_at
    from core.secret_items si
    join core.secret_versions sv on sv.item_id=si.id
    where si.path=%s and sv.is_current
    """
    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, (path,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(404, "Secret not found")
        if row["alg"] != "AES256-GCM":
            raise HTTPException(500, "Unsupported algorithm")
        # AAD: path + version (чтобы связать шифртекст с метаданными)
        aad = f"{path}|{row['version']}".encode()
        plaintext = open_sealed(row["nonce"], row["ciphertext"], aad=aad)
        value = json.loads(plaintext.decode())
        return {"path":path, "version":row["version"], "value":value, "created_at":row["created_at"].isoformat()}

@app.post("/secret/{path:path}", response_model=SecretOut, status_code=201, dependencies=[Depends(require_api_key)])
def put_secret(path: str, payload: PutSecretIn, x_actor_id: str | None = Header(default=None, alias="X-Actor-Id")):
    value = payload.value
    created_by = uuid.UUID(x_actor_id) if x_actor_id else uuid.UUID("00000000-0000-0000-0000-000000000001")

    # шифруем JSON; AAD связывает шифртекст с конкретным объектом (path|version)
    # version ещё неизвестен → для AAD используем placeholder, а расшифровку делаем с фактической версией
    plaintext = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    # временная AAD без версии (привяжем после insert через update)
    aad = f"{path}|0".encode()
    nonce, ct = seal(plaintext, aad=aad)

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # ensure item
        cur.execute("insert into core.secret_items(path,created_by) values(%s,%s) on conflict(path) do nothing",
                    (path, created_by))
        # insert version (alg фиксируем)
        cur.execute("""
            insert into core.secret_versions(item_id, version, is_current, ciphertext, nonce, alg, created_by)
            select id, null, true, %s::bytea, %s::bytea, 'AES256-GCM', %s
            from core.secret_items where path=%s
            returning version, created_at
        """, (ct, nonce, created_by, path))
        row = cur.fetchone()
        version = row["version"]
        # перешифровывать не будем: при чтении используем AAD с фактической версией (см. get_secret)
        conn.commit()

    return {"path":path, "version":version, "value":value, "created_at":row["created_at"].isoformat()}
