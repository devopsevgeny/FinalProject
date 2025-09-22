from pydantic import BaseModel, Field
from typing import Any, Optional

class PutConfigIn(BaseModel):
    value: Any

class ConfigOut(BaseModel):
    path: str
    version: int
    value: Any
    created_at: str

class PutSecretIn(BaseModel):
    value: dict = Field(..., description="Secret payload (e.g., {'username':'u','password':'p'})")

class SecretOut(BaseModel):
    path: str
    version: int
    value: dict
    created_at: str
