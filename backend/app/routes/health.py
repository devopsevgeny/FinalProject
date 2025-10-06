# app/routes/health.py
"""
Health check endpoints for ConfMgr backend.
"""

from fastapi import APIRouter
from psycopg.rows import dict_row
from app.db import pool

router = APIRouter(tags=["health"])

@router.get("/health")
def health():
    """Simple DB round-trip to verify connectivity and time source."""
    with pool.connection() as conn, conn.cursor(row_factory=dict_row) as cur:
        cur.execute("select now()")
        return {"status": "ok", "db_time_utc": cur.fetchone()[0].isoformat()}

@router.get("/healthz")
def healthz():
    """Alias used by probes (e.g. Kubernetes)."""
    return health()
