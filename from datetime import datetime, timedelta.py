from datetime import datetime, timedelta
from typing import Optional
import jwt
from fastapi import HTTPException, status

SECRET_KEY = "your-secret-key"  # Move to environment variable
ALGORITHM = "HS256"

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)