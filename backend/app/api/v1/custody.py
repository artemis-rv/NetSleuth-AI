from fastapi import APIRouter, Depends, Query, Path, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.auth.dependencies import get_current_user, verify_case_access_direct, get_db
from app.persistence.models.identity_models import UserModel
from app.services.custody_service import CustodyService
from app.contracts.api.custody import (
    EvidenceItemListResponse, EvidenceItemResponse,
    CustodyEventListResponse
)
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/custody", tags=["Chain of Custody"])

def get_custody_service(db: AsyncSession = Depends(get_db)) -> CustodyService:
    return CustodyService(db)

@router.get("/cases/{case_id}/evidence-items", response_model=EvidenceItemListResponse)
async def list_case_evidence_items(
    case_id: UUID = Path(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: CustodyService = Depends(get_custody_service)
):
    await verify_case_access_direct(case_id, user, db)
    return await service.list_items_by_case(case_id=case_id, page=page, page_size=page_size)

@router.get("/items/{item_id}", response_model=EvidenceItemResponse)
async def get_evidence_item(
    item_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: CustodyService = Depends(get_custody_service)
):
    item = await service.get_item(item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found")
        
    try:
        await verify_case_access_direct(item.case_id, user, db)
    except Exception as e:
        await log_audit_event(
            db=db,
            action="UNAUTHORIZED_CUSTODY_ACCESS",
            target_entity_type="custody_item",
            target_entity_id=str(item_id),
            result="failure",
            actor_id=user.user_id,
            actor_name=user.username,
            metadata={"reason": "User lacks access to evidence item case"}
        )
        raise e
        
    return item

@router.get("/items/{item_id}/events", response_model=CustodyEventListResponse)
async def list_item_custody_events(
    item_id: UUID = Path(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: CustodyService = Depends(get_custody_service)
):
    item = await service.get_item(item_id)
    if not item:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found")
        
    try:
        await verify_case_access_direct(item.case_id, user, db)
    except Exception as e:
        await log_audit_event(
            db=db,
            action="UNAUTHORIZED_CUSTODY_ACCESS",
            target_entity_type="custody_item",
            target_entity_id=str(item_id),
            result="failure",
            actor_id=user.user_id,
            actor_name=user.username,
            metadata={"reason": "User lacks access to evidence item case"}
        )
        raise e
        
    return await service.list_events_by_item(item_id=item_id, page=page, page_size=page_size)
