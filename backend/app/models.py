"""Pydantic models for API I/O."""

from typing import Any, Literal, Optional

from pydantic import BaseModel


class PutConfigIn(BaseModel):
    """Input model for creating/updating config."""

    app_id: str
    app_name: Optional[str] = None
    value: Any


class ConfigOut(BaseModel):
    """Response model for config item."""

    app_id: str
    app_name: Optional[str] = None
    path: str
    version: int
    data_type: Literal["json", "file"]
    value: Any | None = None
    file_name: Optional[str] = None
    content_type: Optional[str] = None
    file_size: Optional[int] = None
    created_at: str


class PutSecretIn(BaseModel):
    """Input model for creating/updating secret."""

    app_id: str
    app_name: Optional[str] = None
    value: Any


class SecretOut(BaseModel):
    """Response model for secret item."""

    app_id: str
    app_name: Optional[str] = None
    path: str
    version: int
    value: Any
    created_at: str
    mask_response: bool = False


class SecretSummary(BaseModel):
    """Lightweight representation of a secret (no payload)."""

    app_id: str
    app_name: Optional[str] = None
    path: str
    version: int
    created_at: str
