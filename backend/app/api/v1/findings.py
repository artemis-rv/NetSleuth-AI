from fastapi import APIRouter, Depends, Query, status, Path
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from typing import Optional

from app.auth.dependencies import get_current_user, verify_case_access_direct, get_db
from app.persistence.models.identity_models import UserModel
from app.services.findings_service import FindingsService
from app.contracts.api.findings import FindingDetailResponse, FindingListResponse
from app.services.audit_service import log_audit_event

router = APIRouter(tags=["Findings"])

def get_findings_service(db: AsyncSession = Depends(get_db)) -> FindingsService:
    return FindingsService(db)

@router.get(
    "/cases/{case_id}/findings",
    response_model=FindingListResponse,
    summary="List Findings by Case"
)
async def list_case_findings(
    case_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    activity: Optional[str] = Query(None),
    decision_state: Optional[str] = Query(None),
    min_risk: Optional[float] = Query(None),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: FindingsService = Depends(get_findings_service)
):
    await verify_case_access_direct(case_id, user, db)
    
    response = await service.list_findings_by_case(
        case_id=case_id,
        page=page,
        page_size=page_size,
        activity=activity,
        decision_state=decision_state,
        min_risk=min_risk
    )
    return response

@router.get(
    "/findings/{finding_id}",
    response_model=FindingDetailResponse,
    summary="Get Finding Detail"
)
async def get_finding(
    finding_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: FindingsService = Depends(get_findings_service)
):
    # Fetch finding to determine which case it belongs to for authorization
    finding = await service.get_finding(finding_id)
    
    # Authorize against the case
    case_id = await service.get_case_id_for_acquisition(finding.acquisition_id)
    
    if not case_id:
        # Cannot authorize if not linked to a case
        await log_audit_event(
            db=db,
            action="UNAUTHORIZED_FINDING_ACCESS",
            target_entity_type="finding",
            target_entity_id=str(finding_id),
            result="failure",
            actor_id=user.user_id,
            metadata={"reason": "Finding not linked to a case"}
        )
        from fastapi import HTTPException
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
    try:
        await verify_case_access_direct(case_id, user, db)
    except Exception as e:
        await log_audit_event(
            db=db,
            action="UNAUTHORIZED_FINDING_ACCESS",
            target_entity_type="finding",
            target_entity_id=str(finding_id),
            result="failure",
            actor_id=user.user_id,
            metadata={"reason": "User lacks access to finding's case"}
        )
        raise e
        
    await log_audit_event(
        db=db,
        action="FINDING_VIEWED",
        target_entity_type="finding",
        target_entity_id=str(finding_id),
        result="success",
        actor_id=user.user_id
    )
    return finding
