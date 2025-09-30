# app/authz.py
from fastapi import HTTPException

# Super-role: full access everywhere
GLOBAL = "GLOBAL_ADMIN"

def _as_set(principal) -> set[str]:
    return set(principal.scopes or [])

def is_global_admin(principal) -> bool:
    return GLOBAL in _as_set(principal)

def require_roles(principal, *allowed: str) -> None:
    """
    Allow if principal has GLOBAL_ADMIN or any role from `allowed`.
    Otherwise -> 403 Forbidden.
    """
    scopes = _as_set(principal)
    if GLOBAL in scopes:
        return
    if scopes.intersection(allowed):
        return
    raise HTTPException(status_code=403, detail="Forbidden")

# Optional: central action policy mapping
POLICY = {
    "config:get": {"any_of": ["CONFIG_VIEWER", "CONFIG_ADMIN"]},
    "config:put": {"any_of": ["CONFIG_ADMIN"]},
    "secret:get": {"any_of": ["SECRET_VIEWER", "SECRET_ADMIN"]},
    "secret:put": {"any_of": ["SECRET_ADMIN"]},
    "user:list":  {"any_of": ["USER_VIEWER", "USER_ADMIN"]},
    "user:grant": {"any_of": ["USER_ADMIN"]},
}

def allow(principal, action: str) -> None:
    any_of = POLICY[action]["any_of"]
    require_roles(principal, *any_of)
