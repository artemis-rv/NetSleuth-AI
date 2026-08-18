from fastapi import APIRouter, Depends, Query, Path
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.auth.dependencies import get_current_user, verify_case_access_direct, get_db
from app.persistence.models.identity_models import UserModel
from app.services.investigation_service import InvestigationService
from app.contracts.api.investigation import TimelineEventListResponse

router = APIRouter(tags=["Timeline"])

def get_investigation_service(db: AsyncSession = Depends(get_db)) -> InvestigationService:
    return InvestigationService(db)

@router.get("/cases/{case_id}/timeline", response_model=TimelineEventListResponse)
async def list_case_timeline(
    case_id: UUID = Path(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service)
):
    """Retrieve timeline events for a specific case."""
    await verify_case_access_direct(case_id, user, db)
    return await service.list_timeline_by_case(case_id=case_id, page=page, page_size=page_size)
