from fastapi import APIRouter, Depends, Request, Query
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.auth.dependencies import verify_case_access, get_current_user, get_db
from app.persistence.models.identity_models import UserModel
from app.contracts.api.evidence import EvidenceResponse, EvidenceListResponse, EvidenceVerificationResponse
from app.services.evidence_service import EvidenceService

router = APIRouter(tags=["Evidence"])

@router.get("/cases/{case_id}/evidence", response_model=EvidenceListResponse)
async def list_evidence(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List evidence for a specific case.
    """
    service = EvidenceService(db)
    return await service.list_evidence(case_id, current_user, page, page_size)

@router.get("/evidence/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(
    http_request: Request,
    evidence_id: UUID,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve single evidence. 
    Authorization is enforced by resolving the case linkage.
    """
    service = EvidenceService(db)
    ev = await service.get_evidence(evidence_id, current_user, http_request)
    
    # Verify access to the case it belongs to
    from app.persistence.models.investigation_models import case_acquisition_links
    from sqlalchemy import select
    
    stmt = select(case_acquisition_links.c.case_id).where(case_acquisition_links.c.acquisition_id == ev.acquisition_id)
    result = await db.execute(stmt)
    case_id = result.scalar_one_or_none()
    
    if case_id:
        from app.auth.dependencies import verify_case_access_direct
        await verify_case_access_direct(case_id, current_user, db, http_request)
        
    return ev

@router.post("/evidence/{evidence_id}/verify", response_model=EvidenceVerificationResponse)
async def verify_evidence(
    http_request: Request,
    evidence_id: UUID,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Verify the integrity of a specific evidence object against its recorded SHA-256 hash.
    """
    service = EvidenceService(db)
    ev = await service.get_evidence(evidence_id, current_user, http_request) # this will check if exists
    
    # Verify access to the case it belongs to
    from app.persistence.models.investigation_models import case_acquisition_links
    from sqlalchemy import select
    
    stmt = select(case_acquisition_links.c.case_id).where(case_acquisition_links.c.acquisition_id == ev.acquisition_id)
    result = await db.execute(stmt)
    case_id = result.scalar_one_or_none()
    
    if case_id:
        from app.auth.dependencies import verify_case_access_direct
        await verify_case_access_direct(case_id, current_user, db, http_request)
        
    return await service.verify_integrity(evidence_id, current_user, http_request)

@router.get("/evidence/{evidence_id}/export")
async def export_evidence(
    http_request: Request,
    evidence_id: UUID,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Export raw evidence artifact.
    Access restricted to administrator and custodian roles.
    """
    if current_user.role not in ("administrator", "custodian"):
        from app.services.audit_service import log_audit_event, get_client_ip
        await log_audit_event(
            db=db,
            action="EVIDENCE_EXPORT_DENIED",
            target_entity_type="evidence",
            target_entity_id=str(evidence_id),
            result="denied",
            actor_id=current_user.user_id,
            actor_name=current_user.username,
            source_ip=get_client_ip(http_request),
            metadata={"reason": "insufficient_role", "required": ["administrator", "custodian"], "actual": current_user.role}
        )
        await db.commit()
        from fastapi import HTTPException
        raise HTTPException(status_code=403, detail="Direct byte download requires elevated custodian or administrator role.")
        
    service = EvidenceService(db)
    ev = await service.get_evidence(evidence_id, current_user, http_request)
    
    from app.persistence.models.investigation_models import case_acquisition_links
    from sqlalchemy import select
    
    stmt = select(case_acquisition_links.c.case_id).where(case_acquisition_links.c.acquisition_id == ev.acquisition_id)
    result = await db.execute(stmt)
    case_id = result.scalar_one_or_none()
    
    if case_id:
        from app.auth.dependencies import verify_case_access_direct
        await verify_case_access_direct(case_id, current_user, db, http_request)
        
    artifact_bytes, media_type, filename = await service.export_evidence(evidence_id, current_user, http_request)
    
    from fastapi.responses import Response as FastAPIResponse
    headers = {
        "Content-Disposition": f'attachment; filename="{filename}"'
    }
    return FastAPIResponse(content=artifact_bytes, media_type=media_type, headers=headers)
