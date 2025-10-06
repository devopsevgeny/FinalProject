# app/routes/config.py
"""Routes for configuration items (CRUD with versioning, files & audit)."""

import hashlib
import json
import os
from typing import Any

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    Header,
    HTTPException,
    Query,
    UploadFile,
)
from fastapi.responses import StreamingResponse
from psycopg.rows import dict_row
from psycopg.types.json import Json

from app.auth_mode import AUTH_DEP, AUTH_TYPE
from app.db import pool
from app.models import ConfigOut, PutConfigIn
from app.security import AuthPrincipal, resolve_created_by
from app.utils.apps import ensure_app
from app.utils.path_utils import normalize_path

router = APIRouter(prefix="/config", tags=["config"])

MAX_FILE_BYTES = int(os.getenv("CONFIG_FILE_MAX_BYTES", "5242880"))
ALLOWED_FILE_MIME_PREFIXES = tuple(
    prefix.strip()
    for prefix in os.getenv(
        "CONFIG_FILE_ALLOWED_PREFIXES",
        "application/,text/,image/svg+xml",
    ).split(",")
    if prefix.strip()
)


def _actor_subject(
    explicit_subject: str | None,
    principal: AuthPrincipal | None,
) -> str:
    """Resolve actor subject string for audit logs."""
    return (
        explicit_subject
        or (principal.subject if principal else None)
        or ("bearer" if AUTH_TYPE == "BEARER" else "api_key")
    )


def _config_row_to_dict(path: str, row: dict[str, Any]) -> dict[str, Any]:
    """Map DB row to ConfigOut-compatible dict."""
    base: dict[str, Any] = {
        "app_id": row["app_id"],
        "app_name": row["app_name"],
        "path": path,
        "version": row["version"],
        "data_type": row["data_type"],
        "created_at": row["created_at"].isoformat(),
        "value": None,
        "file_name": None,
        "content_type": None,
        "file_size": None,
    }
    if row["data_type"] == "json":
        base["value"] = row["value_json"]
    else:
        base["file_name"] = row.get("file_name")
        base["content_type"] = row.get("content_type")
        base["file_size"] = row.get("file_size")
    return base


def _fetch_current_config(cur, path: str, app_id: str) -> dict[str, Any] | None:
    """Fetch the current config row (with optional file metadata)."""
    cur.execute(
        """
        select
            cv.id,
            cv.version,
            cv.data_type,
            cv.value_json,
            cv.checksum,
            cv.created_at,
            ci.app_id,
            a.app_name,
            cf.file_name,
            cf.content_type,
            cf.file_size
        from core.config_items ci
        join core.config_versions cv on cv.item_id = ci.id
        join core.apps a on a.app_id = ci.app_id
        left join core.config_version_files cf on cf.version_id = cv.id
        where ci.path = %s and ci.app_id = %s and cv.is_current
        """,
        (path, app_id),
    )
    return cur.fetchone()


@router.get("/{path:path}", response_model=ConfigOut)
def get_config(
    path: str,
    app_id: str = Query(default="default", alias="appId"),
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Return the current version of a config value (JSON or file metadata)."""
    path = normalize_path(path)
    app_id = app_id.strip() or "default"
    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        row = _fetch_current_config(cur, path, app_id)
        if not row:
            raise HTTPException(status_code=404, detail="Config not found")
        return _config_row_to_dict(path, row)


@router.post("/{path:path}", response_model=ConfigOut, status_code=201)
def put_config(
    path: str,
    payload: PutConfigIn,
    x_actor_id: str | None = Header(default=None, alias="X-Actor-Id"),
    x_actor_subject: str | None = Header(default=None, alias="X-Actor-Subject"),
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Insert a new JSON config version if changed; audit every write."""
    path = normalize_path(path)
    value = payload.value
    app_id = (payload.app_id or "default").strip() or "default"
    app_name = (payload.app_name or "").strip() or None

    value_canon = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    checksum = hashlib.sha256(value_canon).digest()
    created_by = resolve_created_by(_principal, x_actor_id)

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        ensure_app(cur, app_id, app_name)
        cur.execute("select app_name from core.apps where app_id = %s", (app_id,))
        app_row = cur.fetchone()
        app_display_name = app_row["app_name"] if app_row else app_id

        cur.execute(
            """
            insert into core.config_items(path, app_id, created_by)
            values (%s, %s, %s)
            on conflict(app_id, path) do nothing
            """,
            (path, app_id, created_by),
        )

        current = _fetch_current_config(cur, path, app_id)
        if current and current["data_type"] == "json" and current["checksum"] == checksum:
            return _config_row_to_dict(path, current)

        cur.execute(
            """
            insert into core.config_versions
                (item_id, version, is_current, data_type, value_json, checksum, created_by)
            select id, null, true, 'json', %s::jsonb, %s::bytea, %s
            from core.config_items
            where path = %s and app_id = %s
            returning id, version, created_at
            """,
            (Json(value), checksum, created_by, path, app_id),
        )
        row = cur.fetchone()

        actor_subject = _actor_subject(x_actor_subject, _principal)

        cur.execute(
            "select audit.log_event(%s::uuid, %s::text, %s::text, %s::text, %s::jsonb)",
            (
                created_by,
                actor_subject,
                "config.put",
                path,
                Json({"version": row["version"], "data_type": "json"}),
            ),
        )

        conn.commit()

    return {
        "app_id": app_id,
        "app_name": app_display_name,
        "path": path,
        "version": row["version"],
        "data_type": "json",
        "value": value,
        "file_name": None,
        "content_type": None,
        "file_size": None,
        "created_at": row["created_at"].isoformat(),
    }


@router.post("/{path:path}/file", response_model=ConfigOut, status_code=201)
async def put_config_file(
    path: str,
    file: UploadFile = File(...),
    app_id: str = Form(default="default", alias="appId"),
    app_name: str | None = Form(default=None, alias="appName"),
    mime: str | None = Form(default=None),
    x_actor_id: str | None = Header(default=None, alias="X-Actor-Id"),
    x_actor_subject: str | None = Header(default=None, alias="X-Actor-Subject"),
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Upload a file-backed config item (AES-GCM at rest)."""
    path = normalize_path(path)
    app_id = (app_id or "default").strip() or "default"
    app_name = (app_name or "").strip() or None

    data = await file.read()
    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=400, detail="Config file too large")
    if ALLOWED_FILE_MIME_PREFIXES and mime:
        if not any(mime.startswith(prefix) for prefix in ALLOWED_FILE_MIME_PREFIXES):
            raise HTTPException(status_code=400, detail="Config MIME not allowed")

    created_by = resolve_created_by(_principal, x_actor_id)
    checksum = hashlib.sha256(data).digest()
    safe_name = file.filename or "config.bin"

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        ensure_app(cur, app_id, app_name)
        cur.execute("select app_name from core.apps where app_id = %s", (app_id,))
        app_row = cur.fetchone()
        app_display_name = app_row["app_name"] if app_row else app_id

        cur.execute(
            """
            insert into core.config_items(path, app_id, created_by)
            values (%s, %s, %s)
            on conflict(app_id, path) do nothing
            """,
            (path, app_id, created_by),
        )

        current = _fetch_current_config(cur, path, app_id)
        if current and current["data_type"] == "file" and current["checksum"] == checksum:
            return _config_row_to_dict(path, current)

        cur.execute(
            """
            insert into core.config_versions
                (item_id, version, is_current, data_type, value_json, checksum, created_by)
            select id, null, true, 'file', null, %s::bytea, %s
            from core.config_items
            where path = %s and app_id = %s
            returning id, version, created_at
            """,
            (checksum, created_by, path, app_id),
        )
        ver_row = cur.fetchone()

        cur.execute(
            """
            insert into core.config_version_files
                (version_id, file_name, content_type, file_size, file_data)
            values (%s, %s, %s, %s, %s::bytea)
            """,
            (
                ver_row["id"],
                safe_name,
                mime or "application/octet-stream",
                len(data),
                data,
            ),
        )

        actor_subject = _actor_subject(x_actor_subject, _principal)

        cur.execute(
            "select audit.log_event(%s::uuid, %s::text, %s::text, %s::text, %s::jsonb)",
            (
                created_by,
                actor_subject,
                "config.put",
                path,
                Json({"version": ver_row["version"], "data_type": "file"}),
            ),
        )

        conn.commit()

    return {
        "app_id": app_id,
        "app_name": app_display_name,
        "path": path,
        "version": ver_row["version"],
        "data_type": "file",
        "value": None,
        "file_name": safe_name,
        "content_type": mime or "application/octet-stream",
        "file_size": len(data),
        "created_at": ver_row["created_at"].isoformat(),
    }


@router.get("/{path:path}/file")
def download_config_file(
    path: str,
    version: int | None = Query(default=None),
    app_id: str = Query(default="default", alias="appId"),
    _principal: AuthPrincipal = Depends(AUTH_DEP),
):
    """Stream back the stored file for the given config path/version."""
    path = normalize_path(path)
    app_id = app_id.strip() or "default"

    if version is None:
        version_clause = "cv.is_current"
        params = (path, app_id)
    else:
        version_clause = "cv.version = %s"
        params = (path, app_id, version)

    sql = f"""
        select
            cf.file_name,
            cf.content_type,
            cf.file_size,
            cf.file_data,
            cv.data_type
        from core.config_items ci
        join core.config_versions cv on cv.item_id = ci.id
        join core.config_version_files cf on cf.version_id = cv.id
        where ci.path = %s and ci.app_id = %s and {version_clause}
    """

    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute(sql, params)
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Config file not found")
    if row["data_type"] != "file":
        raise HTTPException(status_code=400, detail="Config is not file-backed")

    content_type = row["content_type"] or "application/octet-stream"
    filename = row["file_name"] or f"{path.replace('/', '_')}"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}

    return StreamingResponse(
        content=bytes(row["file_data"]),
        media_type=content_type,
        headers=headers,
    )
