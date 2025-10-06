# backend/app/deps.py
"""Dependency injection helpers (re-export from auth_mode)."""

from app.auth_mode import AUTH_TYPE, AUTH_DEP  # single source of truth

__all__ = ["AUTH_TYPE", "AUTH_DEP"]
