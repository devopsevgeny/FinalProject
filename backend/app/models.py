"""Pydantic models for API I/O."""
from typing import Any
from pydantic import BaseModel

class PutConfigIn(BaseModel):
    """Input model for creating/updating config."""
    value: Any

class ConfigOut(BaseModel):
    """Response model for config item."""
    path: str
    version: int
    value: Any
    created_at: str

class PutSecretIn(BaseModel):
    """Input model for creating/updating secret."""
    value: Any

class SecretOut(BaseModel):
    """Response model for secret item."""
    path: str
    version: int
    value: Any
    created_at: str
    mask_response: bool = False
