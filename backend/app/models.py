from pydantic import BaseModel, Field
from typing import Any, Dict
from .masking import mask_sensitive_values

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
    value: Dict[str, Any]
    created_at: str
    mask_response: bool = False

    @property
    def masked_value(self) -> Dict[str, Any]:
        """Return masked version of the secret value if masking is enabled"""
        if self.mask_response:
            return mask_sensitive_values(self.value)
        return self.value
