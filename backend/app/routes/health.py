# app/routes/health.py
"""
Health & readiness endpoints for ConfMgr backend.
"""

from __future__ import annotations

import os
from typing import Optional, Tuple, Dict

from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse
from psycopg.rows import dict_row
from psycopg import Error as PsycopgError

from app.db import pool
from app.crypto import seal, open_sealed

router = APIRouter(tags=["health"])


@router.get("/health")
def health() -> Dict[str, str]:
    """Simple DB round-trip to verify connectivity and time source."""
    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("select now() at time zone 'utc' as now_utc")
        row = cur.fetchone()
        if not row or "now_utc" not in row:
            raise HTTPException(status_code=500, detail="DB time probe failed")
        result = {"status": "ok", "db_time_utc": row["now_utc"].isoformat()}
    return result


@router.get("/healthz")
def healthz() -> Dict[str, str]:
    """Alias used by probes (e.g., Kubernetes)."""
    result = health()
    return result


def _check_db() -> Tuple[bool, Optional[str]]:
    """Verify DB connectivity and a core table presence."""
    ok = False
    err: Optional[str] = None
    try:
        with pool.connection() as conn, conn.cursor() as cur:
            cur.execute("select 1")
            cur.fetchone()
            cur.execute("select to_regclass('core.config_items')")
            result = cur.fetchone()
            if result and result[0] is not None:
                ok = True
            else:
                ok = False
                err = "required table core.config_items not found"
    except (PsycopgError, KeyError, TypeError) as exc:
        ok = False
        err = str(exc)
    return ok, err


def _check_crypto() -> Tuple[bool, Optional[str]]:
    """Verify AES-GCM round-trip (ensures DATA_KEY_HEX is usable)."""
    ok = False
    err: Optional[str] = None
    try:
        nonce, ct = seal(b"rdz", aad=b"readyz")
        ok = open_sealed(nonce, ct, aad=b"readyz") == b"rdz"
        if not ok:
            err = "crypto round-trip mismatch"
    except (ValueError, RuntimeError) as exc:
        ok = False
        err = str(exc)
    return ok, err


def _check_auth() -> Tuple[bool, Optional[str]]:
    """Validate auth-related configuration for selected AUTH_TYPE."""
    ok = True
    err: Optional[str] = None
    try:
        auth_type = os.getenv("AUTH_TYPE", "API_KEY").strip().upper()
        if auth_type not in ("API_KEY", "BEARER"):
            ok, err = False, f"invalid AUTH_TYPE: {auth_type}"
        elif auth_type == "BEARER":
            alg = os.getenv("JWT_ALG", "HS256").strip().upper()
            if alg.startswith("HS"):
                if not os.getenv("JWT_SIGNING_KEY"):
                    ok, err = False, "JWT_SIGNING_KEY missing for HS*"
            else:
                if not os.getenv("JWT_PRIVATE_KEY"):
                    ok, err = False, "JWT_PRIVATE_KEY missing for RS*/ES*"
            if ok and not os.getenv("JWT_AUDIENCE"):
                ok, err = False, "JWT_AUDIENCE missing"
            if ok and not os.getenv("ISSUER"):
                ok, err = False, "ISSUER missing"
    except ValueError as exc:
        ok, err = False, str(exc)
    return ok, err


@router.get("/readyz")
def readyz() -> JSONResponse:
    """
    Readiness probe:
    - DB reachable and schema present.
    - Crypto key usable (AES-GCM round-trip).
    - Auth configuration sane for selected AUTH_TYPE.
    """
    db_ok, db_err = _check_db()
    crypto_ok, crypto_err = _check_crypto()
    auth_ok, auth_err = _check_auth()

    ok = db_ok and crypto_ok and auth_ok
    issues = {}
    if db_err:
        issues["db"] = db_err
    if crypto_err:
        issues["crypto"] = crypto_err
    if auth_err:
        issues["auth"] = auth_err

    content = {
        "status": "ok" if ok else "degraded",
        "checks": {"db": db_ok, "crypto": crypto_ok, "auth": auth_ok},
        "issues": issues,
    }
    status = 200 if ok else 503
    return JSONResponse(status_code=status, content=content)
