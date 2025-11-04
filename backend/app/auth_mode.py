# app/auth_mode.py
"""
Selects authentication mode for the backend (API_KEY or BEARER).
"""

import os
from typing import TYPE_CHECKING, Callable
from app.security import require_api_key, require_bearer

if TYPE_CHECKING:
    from app.security.auth import AuthPrincipal

AuthDependency = Callable[..., "AuthPrincipal"]

AUTH_TYPE = os.getenv("AUTH_TYPE", "API_KEY").strip().upper()
AUTH_DEP: AuthDependency

if AUTH_TYPE == "API_KEY":
    AUTH_DEP = require_api_key
elif AUTH_TYPE == "BEARER":
    AUTH_DEP = require_bearer
else:
    raise RuntimeError(f"Invalid AUTH_TYPE '{AUTH_TYPE}'. Expected 'API_KEY' or 'BEARER'.")
