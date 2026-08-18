from fastapi import APIRouter, Depends, Path
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.auth.dependencies import get_current_user, verify_case_access_direct, get_db
from app.persistence.models.identity_models import UserModel
from app.services.investigation_service import InvestigationService
from app.contracts.api.investigation import GraphResponse

router = APIRouter(tags=["Graph"])

def get_investigation_service(db: AsyncSession = Depends(get_db)) -> InvestigationService:
    return InvestigationService(db)

@router.get("/cases/{case_id}/graph", response_model=GraphResponse)
async def get_case_graph(
    case_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service)
):
    """Retrieve investigation graph for a specific case."""
    await verify_case_access_direct(case_id, user, db)
    return await service.get_graph_by_case(case_id=case_id)
