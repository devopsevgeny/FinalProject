import os, psycopg
from psycopg_pool import ConnectionPool  # встроен в psycopg[binary]

def _conn_str() -> str:
    # libpq варианты читаются из окружения (PGHOST, PGUSER, PGDATABASE и т.д.)
    return ""

pool = ConnectionPool(
    conninfo=_conn_str(),
    kwargs=dict(
        host=os.getenv("PGHOST", "postgres"),
        dbname=os.getenv("PGDATABASE", "postgres"),
        user=os.getenv("PGUSER", "confmgr_db"),
        sslmode=os.getenv("PGSSLMODE", "verify-full"),
        sslrootcert=os.getenv("PGSSLROOTCERT"),
        sslcert=os.getenv("PGSSLCERT"),
        sslkey=os.getenv("PGSSLKEY"),
        connect_timeout=5,
    ),
    max_size=int(os.getenv("DB_POOL_MAX", "10")),
    timeout=10,
)

def qrow(sql: str, params: tuple | None = None):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            return cur.fetchone()

def qexec(sql: str, params: tuple | None = None):
    with pool.connection() as conn:
        with conn.cursor() as cur:
            cur.execute(sql, params or ())
            conn.commit()
