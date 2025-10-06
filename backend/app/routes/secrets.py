# backend/app/routes/secrets.py
"""Routes for secrets (AES-GCM at rest) with versioning & audit."""

import json

from fastapi import APIRouter, Depends, Header, HTTPException, Query
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.db import pool
from app.crypto import seal, open_sealed
from app.models import PutSecretIn, SecretOut
from app.security import AuthPrincipal, resolve_created_by
from app.auth_mode import AUTH_TYPE, AUTH_DEP
from app.utils.path_utils import normalize_path

router = APIRouter(prefix="/secret", tags=["secrets"])


@router.get("/{path:path}", response_model=SecretOut)
def get_secret(
    path: str,
    version: int | None = Query(default=None),
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Fetch and decrypt secret; if version omitted, use current."""
    path = normalize_path(path)
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
            raise HTTPException(status_code=404, detail="Secret not found")
        if row["alg"] != "AES256-GCM":
            raise HTTPException(status_code=500, detail="Unsupported algorithm")

        aad = f"{path}|{row['version']}".encode()
        plaintext = open_sealed(row["nonce"], row["ciphertext"], aad=aad)

        return SecretOut(
            path=path,
            version=row["version"],
            value=json.loads(plaintext.decode()),
            created_at=row["created_at"].isoformat(),
            mask_response=False,
        )


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
    created_by = resolve_created_by(_principal, x_actor_id)

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Ensure parent item exists
        cur.execute(
            "insert into core.secret_items(path, created_by) values (%s, %s) "
            "on conflict(path) do nothing",
            (path, created_by),
        )

        # Lock parent and compute next version
        cur.execute("select id from core.secret_items where path = %s for update", (path,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=500, detail="Secret item not created")
        item_id = row["id"]

        cur.execute(
            "select coalesce(max(version), 0) + 1 as next_ver "
            "from core.secret_versions where item_id = %s",
            (item_id,),
        )
        next_ver = cur.fetchone()["next_ver"]

        # Encrypt with AAD bound to (path|version)
        plaintext = json.dumps(payload.value, separators=(",", ":"), sort_keys=True).encode()
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
        path=path,
        version=ver_row["version"],
        value=payload.value,
        created_at=ver_row["created_at"].isoformat(),
        mask_response=True,
    )
