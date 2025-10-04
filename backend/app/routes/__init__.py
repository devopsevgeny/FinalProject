# app/routes/__init__.py
from fastapi import APIRouter
from .login import router as login_router
from .whoami import router as whoami_router

router = APIRouter()
router.include_router(login_router)
router.include_router(whoami_router)

