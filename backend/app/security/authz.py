# backend/app/security/authz.py
"""Authorization helpers (RBAC: roles → policy checks)."""

from __future__ import annotations

from typing import Iterable
from fastapi import HTTPException

# Role with full access
GLOBAL_ROLE = "GLOBAL_ADMIN"


def _as_role_set(principal) -> set[str]:
    """Return principal roles as a set (empty if missing)."""
    return set(principal.roles or [])


def is_global_admin(principal) -> bool:
    """True if principal has GLOBAL_ADMIN."""
    return GLOBAL_ROLE in _as_role_set(principal)


def require_roles(principal, *allowed: Iterable[str]) -> None:
    """Allow if principal has GLOBAL_ADMIN or any role from `allowed`; else 403."""
    roles = _as_role_set(principal)
    if GLOBAL_ROLE in roles:
        return
    if roles.intersection(set(allowed)):
        return
    raise HTTPException(status_code=403, detail="Forbidden")


# Central action→policy map (example)
POLICY: dict[str, dict[str, list[str]]] = {
    "config:get": {"any_of": ["CONFIG_VIEWER", "CONFIG_ADMIN", GLOBAL_ROLE]},
    "config:put": {"any_of": ["CONFIG_ADMIN", GLOBAL_ROLE]},
    "secret:get": {"any_of": ["SECRET_VIEWER", "SECRET_ADMIN", GLOBAL_ROLE]},
    "secret:put": {"any_of": ["SECRET_ADMIN", GLOBAL_ROLE]},
    "user:list": {"any_of": ["USER_VIEWER", "USER_ADMIN", GLOBAL_ROLE]},
    "user:grant": {"any_of": ["USER_ADMIN", GLOBAL_ROLE]},
}


def allow(principal, action: str) -> None:
    """Check policy for `action` using principal roles; raise 403 if not allowed."""
    rule = POLICY.get(action)
    if not rule:
        # Unknown action → deny by default (fail closed)
        raise HTTPException(status_code=403, detail="Forbidden")
    require_roles(principal, *rule.get("any_of", []))
