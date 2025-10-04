# app/deps.py
import os
from app.security.auth import require_api_key, require_bearer

# Resolve auth mode once and expose the proper dependency for routers.
AUTH_TYPE = os.getenv("AUTH_TYPE", "API_KEY").strip().upper()
if AUTH_TYPE == "API_KEY":
    AUTH_DEP = require_api_key
elif AUTH_TYPE == "BEARER":
    AUTH_DEP = require_bearer
else:
    raise RuntimeError(f"Invalid AUTH_TYPE '{AUTH_TYPE}'. Expected 'API_KEY' or 'BEARER'.")
