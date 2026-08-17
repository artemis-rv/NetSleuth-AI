"""
backend/app/api/router.py
-------------------------
Root API Router for NetSleuth-AI.

Mounts versioned API routers (e.g. /api/v1).
"""

from fastapi import APIRouter
from app.api.v1 import v1_router

api_router = APIRouter(prefix="/api")

# Mount API versions
api_router.include_router(v1_router)

__all__ = ["api_router"]
