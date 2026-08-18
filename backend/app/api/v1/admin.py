"""
backend/app/api/v1/admin.py
---------------------------
Admin API Router boundary (APP-0 structural placeholder).
"""

from fastapi import APIRouter, Depends

from app.auth.dependencies import RequireRole
from app.persistence.models.identity_models import UserModel

router = APIRouter(prefix="/admin", tags=["Admin"])

@router.get("/system-status")
async def get_system_status(
    current_user: UserModel = Depends(RequireRole(["administrator"]))
):
    """
    Retrieve system status.
    Protected by RequireRole ensuring only administrators can access.
    """
    return {
        "status": "online",
        "message": f"Administrator {current_user.username} successfully accessed system status."
    }
