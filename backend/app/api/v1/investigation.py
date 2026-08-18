from fastapi import APIRouter, Depends, Query, Path, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.auth.dependencies import get_current_user, verify_case_access_direct, get_db
from app.persistence.models.identity_models import UserModel
from app.services.investigation_service import InvestigationService
from app.contracts.api.investigation import (
    EntityListResponse, EntityResponse,
    RelationshipListResponse, RelationshipResponse,
    BehaviorListResponse,
    TimelineEventListResponse,
    MitreMappingListResponse,
    AttackChainResponse,
    GraphResponse
)
from app.services.audit_service import log_audit_event

router = APIRouter(tags=["Investigation"])

def get_investigation_service(db: AsyncSession = Depends(get_db)) -> InvestigationService:
    return InvestigationService(db)

@router.get("/cases/{case_id}/entities", response_model=EntityListResponse)
async def list_case_entities(
    case_id: UUID = Path(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service)
):
    await verify_case_access_direct(case_id, user, db)
    return await service.list_entities_by_case(case_id=case_id, page=page, page_size=page_size)

@router.get("/entities/{entity_id}", response_model=EntityResponse)
async def get_entity(
    entity_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service)
):
    entity = await service.get_entity(entity_id)
    if not entity:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entity not found")
        
    try:
        await verify_case_access_direct(entity.case_id, user, db)
    except Exception as e:
        await log_audit_event(db, "UNAUTHORIZED_ENTITY_ACCESS", user.user_id, str(entity_id), "User lacks access to entity's case")
        raise e
        
    return entity

@router.get("/cases/{case_id}/relationships", response_model=RelationshipListResponse)
async def list_case_relationships(
    case_id: UUID = Path(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service)
):
    await verify_case_access_direct(case_id, user, db)
    return await service.list_relationships_by_case(case_id=case_id, page=page, page_size=page_size)

@router.get("/relationships/{relationship_id}", response_model=RelationshipResponse)
async def get_relationship(
    relationship_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service)
):
    relationship = await service.get_relationship(relationship_id)
    if not relationship:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Relationship not found")
        
    try:
        await verify_case_access_direct(relationship.case_id, user, db)
    except Exception as e:
        await log_audit_event(db, "UNAUTHORIZED_RELATIONSHIP_ACCESS", user.user_id, str(relationship_id), "User lacks access to relationship's case")
        raise e
        
    return relationship

@router.get("/cases/{case_id}/behaviors", response_model=BehaviorListResponse)
async def list_case_behaviors(
    case_id: UUID = Path(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service)
):
    await verify_case_access_direct(case_id, user, db)
    return await service.list_behaviors_by_case(case_id=case_id, page=page, page_size=page_size)

@router.get("/cases/{case_id}/mitre", response_model=MitreMappingListResponse)
async def list_case_mitre_mappings(
    case_id: UUID = Path(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service)
):
    await verify_case_access_direct(case_id, user, db)
    return await service.list_mitre_mappings_by_case(case_id=case_id, page=page, page_size=page_size)

@router.get("/cases/{case_id}/attack-chain", response_model=AttackChainResponse)
async def get_case_attack_chain(
    case_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service)
):
    await verify_case_access_direct(case_id, user, db)
    return await service.get_attack_chain_by_case(case_id=case_id)

