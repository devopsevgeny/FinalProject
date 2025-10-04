# app/routes/whoami.py
from fastapi import APIRouter, Depends
from app.deps import AUTH_TYPE, AUTH_DEP
from app.security.auth import AuthPrincipal

router = APIRouter(tags=["meta"])

@router.get("/whoami")
def whoami(principal: AuthPrincipal = Depends(AUTH_DEP)):
    """Public whoami endpoint."""
    return {
        "auth_type": AUTH_TYPE,
        "principal": {
            "id": principal.id,
            "subject": principal.subject,
            "issuer": principal.issuer,
            "roles": principal.roles or [],
            "scopes": principal.scopes or [],
        },
    }

@router.get("/__whoami")
def internal_whoami(principal: AuthPrincipal = Depends(AUTH_DEP)):
    """Internal diag endpoint showing auth mode and principal details."""
    return {
        "auth_type": AUTH_TYPE,
        "principal": {
            "id": principal.id,
            "subject": principal.subject,
            "issuer": principal.issuer,
            "roles": principal.roles or [],
            "scopes": principal.scopes or [],
        },
    }
