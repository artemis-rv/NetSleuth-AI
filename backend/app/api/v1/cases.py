"""
backend/app/api/v1/cases.py
---------------------------
Cases API Router boundary (APP-0 structural placeholder).
"""

from fastapi import APIRouter, Depends, Request, status, Query
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID

from app.auth.dependencies import verify_case_access, get_current_user, RequireRole, get_db
from app.persistence.models.identity_models import UserModel
from app.contracts.api.cases import CreateCaseRequest, UpdateCaseRequest, CaseResponse, CaseListResponse
from app.services.case_service import CaseService

router = APIRouter(prefix="/cases", tags=["Cases"])

@router.post("", response_model=CaseResponse, status_code=status.HTTP_201_CREATED)
async def create_case(
    request_data: CreateCaseRequest,
    http_request: Request,
    current_user: UserModel = Depends(RequireRole(["administrator", "investigator"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Create a new investigation case.
    Only Administrators and Investigators can create cases.
    """
    service = CaseService(db)
    return await service.create_case(current_user, request_data, http_request)

@router.get("", response_model=CaseListResponse)
async def list_cases(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Items per page"),
    status: Optional[str] = Query(None, description="Filter by status"),
    priority: Optional[str] = Query(None, description="Filter by priority"),
    sort_by: str = Query("created_at", description="Sort field (created_at, updated_at, priority, status)"),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List accessible investigation cases with pagination and optional filtering.
    Administrators see all. Investigators/Analysts see assigned.
    """
    service = CaseService(db)
    return await service.list_cases(
        current_user=current_user,
        page=page,
        page_size=page_size,
        status=status,
        priority=priority,
        sort_by=sort_by
    )

@router.get("/{case_id}", response_model=CaseResponse)
async def get_case(
    case_id: UUID,
    http_request: Request,
    verified_case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve case details.
    Protected by verify_case_access which ensures the user has read permissions.
    """
    service = CaseService(db)
    return await service.get_case(verified_case_id, current_user, http_request)

@router.patch("/{case_id}", response_model=CaseResponse)
async def update_case(
    case_id: UUID,
    update_data: UpdateCaseRequest,
    http_request: Request,
    verified_case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Update a specific case.
    Only allowed fields can be modified.
    """
    service = CaseService(db)
    return await service.update_case(verified_case_id, update_data, current_user, http_request)
