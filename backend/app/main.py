"""
Main entrypoint for ConfMgr backend.
Initializes FastAPI app, logging, CORS, and includes route aggregator.
"""

import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.logging_config import setup_logging
from app.routes import router as routes

# Initialize logging and app
setup_logging()
app = FastAPI(title="confmgr-backend")

# ---------- CORS ----------
# Allowed origins (comma-separated). Default: http://localhost:5173
raw_origins = os.getenv("CORS_ORIGINS", "http://localhost:5173")
origins = [o.strip() for o in raw_origins.split(",") if o.strip()]
allow_all = any(o == "*" for o in origins)
if allow_all:
    origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=not allow_all,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Actor-Id",
        "X-Actor-Subject",
    ],
)

# ---------- Include Routes ----------
app.include_router(routes)
