
# app/routes/__init__.py
"""
Aggregates all routers for ConfMgr backend.
"""

from fastapi import APIRouter

# Import subrouters explicitly (no relative import from main)
from app.routes import health, login, whoami, config, secrets

router = APIRouter()

# Include routers in a consistent order
router.include_router(health.router)
router.include_router(login.router)
router.include_router(whoami.router)
router.include_router(config.router)
router.include_router(secrets.router)
