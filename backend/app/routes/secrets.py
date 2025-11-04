# backend/app/routes/secrets.py
"""Routes for secrets (AES-GCM at rest) with versioning & audit."""

import json
from typing import Any, Dict, Tuple

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.db import pool
from app.crypto import seal, open_sealed
from app.models import PutSecretIn, SecretOut, SecretSummary
from app.security import AuthPrincipal, resolve_created_by
from app.auth_mode import AUTH_TYPE, AUTH_DEP
from app.utils.path_utils import normalize_path
from app.utils.apps import ensure_app

router = APIRouter(prefix="/secret", tags=["secrets"])


def _decrypt_secret(path: str, row: Dict[str, Any]) -> Dict[str, Any]:
    if row["alg"] != "AES256-GCM":
        raise HTTPException(status_code=500, detail="Unsupported algorithm")
    aad = f"{path}|{row['version']}".encode()
    plaintext = open_sealed(row["nonce"], row["ciphertext"], aad=aad)
    try:
        value = json.loads(plaintext.decode())
    except json.JSONDecodeError:
        raise HTTPException(status_code=500, detail="Malformed secret payload")
    return {
        "app_id": row.get("app_id"),
        "app_name": row.get("app_name"),
        "path": path,
        "version": row["version"],
        "value": value,
        "created_at": row["created_at"].isoformat(),
    }


@router.get("/", response_model=list[SecretSummary])
def list_secrets(
    app_id: str = Query(default="default", alias="appId"),
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Return the list of secret paths with their current version."""
    app_id = app_id.strip() or "default"
    sql = """
    select si.path, sv.version, sv.created_at, si.app_id, a.app_name
    from core.secret_items si
    join core.secret_versions sv on sv.item_id = si.id and sv.is_current
    join core.apps a on a.app_id = si.app_id
    where si.app_id = %s
    order by si.path
    """
    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, (app_id,))
        rows = cur.fetchall()
        return [
            SecretSummary(
                app_id=row["app_id"],
                app_name=row["app_name"],
                path=row["path"],
                version=row["version"],
                created_at=row["created_at"].isoformat(),
            )
            for row in rows
        ]

@router.get("/all", response_model=list[SecretOut])
def get_all_secrets(
    app_id: str = Query(default="default", alias="appId"),
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Return every current secret with decrypted payload for an app (restricted use)."""
    app_id = app_id.strip() or "default"
    sql = """
    select si.path, sv.version, sv.ciphertext, sv.nonce, sv.alg, sv.created_at, si.app_id, a.app_name
    from core.secret_items si
    join core.secret_versions sv on sv.item_id = si.id
    join core.apps a on a.app_id = si.app_id
    where sv.is_current and si.app_id = %s
    order by si.path
    """
    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, (app_id,))
        rows = cur.fetchall()
        secrets = [_decrypt_secret(row["path"], row) for row in rows]
        return [
            SecretOut(**secret, mask_response=True)
            for secret in secrets
        ]


@router.get("/{path:path}", response_model=SecretOut)
def get_secret(
    path: str,
    version: int | None = Query(default=None),
    app_id: str = Query(default="default", alias="appId"),
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Fetch and decrypt secret; if version omitted, use current."""
    path = normalize_path(path)
    app_id = app_id.strip() or "default"
    if version is None:
        sql = """
        select sv.version, sv.ciphertext, sv.nonce, sv.alg, sv.created_at, si.app_id, a.app_name
        from core.secret_items si
        join core.secret_versions sv on sv.item_id = si.id
        join core.apps a on a.app_id = si.app_id
        where si.path = %s and si.app_id = %s and sv.is_current
        """
        params: Tuple[Any, ...] = (path, app_id)
    else:
        sql = """
        select sv.version, sv.ciphertext, sv.nonce, sv.alg, sv.created_at, si.app_id, a.app_name
        from core.secret_items si
        join core.secret_versions sv on sv.item_id = si.id
        join core.apps a on a.app_id = si.app_id
        where si.path = %s and si.app_id = %s and sv.version = %s
        """
        params = (path, app_id, version)

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Secret not found")
        secret = _decrypt_secret(path, row)
        return SecretOut(**secret, mask_response=False)


@router.post("/{path:path}", response_model=SecretOut, status_code=201)
def put_secret(
    path: str,
    payload: PutSecretIn,
    x_actor_id: str | None = Header(default=None, alias="X-Actor-Id"),
    x_actor_subject: str | None = Header(default=None, alias="X-Actor-Subject"),
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Insert/update secret with AES-GCM encryption and audit."""
    path = normalize_path(path)
    value = payload.value
    app_id = (payload.app_id or "default").strip() or "default"
    app_name = (payload.app_name or "").strip() or None
    created_by = resolve_created_by(_principal, x_actor_id)

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        ensure_app(cur, app_id, app_name)
        cur.execute("select app_name from core.apps where app_id = %s", (app_id,))
        app_row = cur.fetchone()
        app_display_name = app_row["app_name"] if app_row else app_id

        # Ensure parent item exists
        cur.execute(
            "insert into core.secret_items(path, app_id, created_by) values (%s, %s, %s) "
            "on conflict(app_id, path) do nothing",
            (path, app_id, created_by),
        )

        # Lock parent and compute next version
        cur.execute(
            "select id from core.secret_items where path = %s and app_id = %s for update",
            (path, app_id),
        )
        row = cur.fetchone()
        if row is None:
            raise HTTPException(status_code=500, detail="Secret item not created")
        item_id = row["id"]

        cur.execute(
            "select coalesce(max(version), 0) + 1 as next_ver "
            "from core.secret_versions where item_id = %s",
            (item_id,),
        )
        ver_meta = cur.fetchone()
        if ver_meta is None:
            raise HTTPException(status_code=500, detail="Secret version sequence failed")
        next_ver = ver_meta["next_ver"]

        # Encrypt with AAD bound to (path|version)
        plaintext = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
        nonce, ct = seal(plaintext, aad=f"{path}|{next_ver}".encode())

        # Flip current and insert new current version
        cur.execute(
            "update core.secret_versions set is_current = false "
            "where item_id = %s and is_current",
            (item_id,),
        )
        cur.execute(
            """
            insert into core.secret_versions
                (item_id, version, is_current, ciphertext, nonce, alg, created_by)
            values (%s, %s, true, %s::bytea, %s::bytea, 'AES256-GCM', %s)
            returning version, created_at
            """,
            (item_id, next_ver, ct, nonce, created_by),
        )
        ver_row = cur.fetchone()
        if ver_row is None:
            raise HTTPException(status_code=500, detail="Secret version insert failed")

        # Audit (single execute; keep width by splitting args)
        audit_sql = (
            "select audit.log_event("
            "%s::uuid,%s::text,%s::text,%s::text,%s::jsonb)"
        )
        cur.execute(
            audit_sql,
            (
                created_by,
                x_actor_subject
                or (_principal.subject if _principal else None)
                or ("bearer" if AUTH_TYPE == "BEARER" else "api_key"),
                "secret.put",
                path,
                Json({"version": ver_row["version"]}),
            ),
        )

        conn.commit()

    return SecretOut(
        app_id=app_id,
        app_name=app_display_name,
        path=path,
        version=ver_row["version"],
        value=value,
        created_at=ver_row["created_at"].isoformat(),
        mask_response=True,
    )
