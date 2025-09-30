# app/routes/__init__.py
from fastapi import APIRouter
from .login import router as login_router

router = APIRouter()
router.include_router(login_router)
