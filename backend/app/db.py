"""Database connection pool."""

import os
from psycopg_pool import ConnectionPool

def _conninfo() -> str:
    """
    Use libpq env (PGHOST, PGUSER, PGDATABASE, PGSSLMODE, PGSSLROOTCERT, PGSSLCERT, PGSSLKEY, etc.).
    Keep empty string to let psycopg read from environment.
    Optional: override via PG_CONNINFO if provided.
    """
    return os.getenv("PG_CONNINFO", "")

pool = ConnectionPool(
    conninfo=_conninfo(),
    min_size=1,
    max_size=int(os.getenv("DB_POOL_MAX", "10")),
    timeout=10,
)

def qrow(sql: str, params: tuple | None = None):
    """Execute a query and return the first row (or None)."""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params or ())
        return cur.fetchone()

def qexec(sql: str, params: tuple | None = None) -> None:
    """Execute a statement and commit."""
    with pool.connection() as conn, conn.cursor() as cur:
        cur.execute(sql, params or ())
        conn.commit()
