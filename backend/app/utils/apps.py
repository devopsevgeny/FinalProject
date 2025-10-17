"""Helpers for managing application registry (core.apps)."""
from psycopg import Cursor


def ensure_app(cur: Cursor, app_id: str, app_name: str | None = None) -> str:
    """
    Ensure an app row exists. If app_name is provided, update it; otherwise
    create the row with app_id as the name and keep existing name on conflict.
    Returns the normalized app_id.
    """
    if not app_id or not app_id.strip():
        raise ValueError("app_id must be provided")

    normalized_id = app_id.strip()

    if app_name and app_name.strip():
        cur.execute(
            """
            insert into core.apps(app_id, app_name)
            values (%s, %s)
            on conflict(app_id) do update
            set app_name = excluded.app_name
            """,
            (normalized_id, app_name.strip()),
        )
    else:
        cur.execute(
            """
            insert into core.apps(app_id, app_name)
            values (%s, %s)
            on conflict(app_id) do nothing
            """,
            (normalized_id, normalized_id),
        )

    return normalized_id
