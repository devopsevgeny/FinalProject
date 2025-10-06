# app/routes/config.py
"""Routes for configuration items (CRUD with versioning & audit)."""

import json
import hashlib
from fastapi import APIRouter, Depends, Header, HTTPException
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.db import pool
from app.models import PutConfigIn, ConfigOut
from app.security import AuthPrincipal, resolve_created_by
from app.auth_mode import AUTH_TYPE, AUTH_DEP
from app.utils.path_utils import normalize_path

router = APIRouter(prefix="/config", tags=["config"])


@router.get("/{path:path}", response_model=ConfigOut)
def get_config(
    path: str,
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Return the current version of a config value."""
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
            raise HTTPException(status_code=404, detail="Config not found")
        return {
            "path": path,
            "version": row["version"],
            "value": row["value_json"],
            "created_at": row["created_at"].isoformat(),
        }


@router.post("/{path:path}", response_model=ConfigOut, status_code=201)
def put_config(
    path: str,
    payload: PutConfigIn,
    x_actor_id: str | None = Header(default=None, alias="X-Actor-Id"),
    x_actor_subject: str | None = Header(default=None, alias="X-Actor-Subject"),
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Insert a new config version if changed; audit every write."""
    path = normalize_path(path)
    value = payload.value

    # Deterministic checksum over canonical JSON
    value_canon = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    checksum = hashlib.sha256(value_canon).digest()
    created_by = resolve_created_by(_principal, x_actor_id)

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        # Ensure item exists
        cur.execute(
            "insert into core.config_items(path, created_by) "
            "values (%s, %s) on conflict(path) do nothing",
            (path, created_by),
        )

        # If current version has the same checksum — return it (idempotent)
        cur.execute(
            """
            select cv.version, cv.checksum, cv.created_at
            from core.config_items ci
            join core.config_versions cv on cv.item_id = ci.id
            where ci.path = %s and cv.is_current
            """,
            (path,),
        )
        current = cur.fetchone()
        if current and current["checksum"] == checksum:
            return {
                "path": path,
                "version": current["version"],
                "value": value,
                "created_at": current["created_at"].isoformat(),
            }

        # Insert new current version (DB default/trigger bumps version)
        cur.execute(
            """
            insert into core.config_versions
                (item_id, version, is_current, value_json, checksum, created_by)
            select id, null, true, %s::jsonb, %s::bytea, %s
            from core.config_items
            where path = %s
            returning version, created_at
            """,
            (Json(value), checksum, created_by, path),
        )
        row = cur.fetchone()

        # Derive actor_subject (JWT → header → fallback by auth type)
        actor_subject = (
            x_actor_subject
            or (_principal.subject if _principal else None)
            or ("bearer" if AUTH_TYPE == "BEARER" else "api_key")
        )

        # Audit
        cur.execute(
            "select audit.log_event(%s::uuid, %s::text, %s::text, %s::text, %s::jsonb)",
            (
                created_by,
                actor_subject,
                "config.put",
                path,
                Json({"version": row["version"]}),
            ),
        )

        conn.commit()

    return {
        "path": path,
        "version": row["version"],
        "value": value,
        "created_at": row["created_at"].isoformat(),
    }
