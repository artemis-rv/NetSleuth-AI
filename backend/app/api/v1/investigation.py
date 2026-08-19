from fastapi import APIRouter, Depends, Query, Path, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.auth.dependencies import get_current_user, verify_case_access_direct, get_db
from app.persistence.models.identity_models import UserModel
from app.services.investigation_service import InvestigationService
from app.contracts.api.investigation import (
    EntityListResponse, EntityResponse,
    RelationshipListResponse, RelationshipResponse,
    BehaviorListResponse, BehaviorDetailResponse,
    TimelineEventListResponse, TimelineEventResponse,
    MitreMappingListResponse, MitreMappingResponse,
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
        await log_audit_event(
            db=db,
            action="UNAUTHORIZED_ENTITY_ACCESS",
            target_entity_type="entity",
            target_entity_id=str(entity_id),
            result="failure",
            actor_id=user.user_id,
            metadata={"reason": "User lacks access to entity's case"}
        )
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
        await log_audit_event(
            db=db,
            action="UNAUTHORIZED_RELATIONSHIP_ACCESS",
            target_entity_type="relationship",
            target_entity_id=str(relationship_id),
            result="failure",
            actor_id=user.user_id,
            metadata={"reason": "User lacks access to relationship's case"}
        )
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

@router.get("/cases/{case_id}/behaviors/{behavior_id}", response_model=BehaviorDetailResponse)
async def get_case_behavior_detail(
    case_id: UUID = Path(...),
    behavior_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: InvestigationService = Depends(get_investigation_service)
):
    await verify_case_access_direct(case_id, user, db)
    
    # Audit log access
    await log_audit_event(
        db=db,
        action="BEHAVIOR_DETAIL_ACCESS",
        target_entity_type="behavior",
        target_entity_id=str(behavior_id),
        result="success",
        actor_id=user.user_id,
        metadata={"case_id": str(case_id)}
    )
    
    detail = await service.get_behavior_detail(behavior_id)

    # Ensure the behavior actually belongs to this case
    if detail["behavior"].case_id != case_id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Behavior not found in this case")
        
    # Map the service response to the BehaviorDetailResponse contract
    behavior = detail["behavior"]
    
    # Calculate or extract severity from attributes or finding
    severity = getattr(behavior, 'severity', None)
    if not severity and behavior.attributes and isinstance(behavior.attributes, dict):
        severity = behavior.attributes.get("severity") or behavior.attributes.get("risk_level")
    if not severity:
        confidence = getattr(behavior, 'confidence', 0.8) or 0.8
        severity = "critical" if confidence >= 0.9 else ("high" if confidence >= 0.7 else "medium")

    first_obs = getattr(behavior, 'first_observed', None)
    last_obs = getattr(behavior, 'last_observed', None)
    if not first_obs and detail["timeline_events"]:
        first_obs = detail["timeline_events"][0].event_timestamp
        last_obs = detail["timeline_events"][-1].event_timestamp

    desc = None
    if behavior.attributes and isinstance(behavior.attributes, dict):
        desc = behavior.attributes.get("description") or behavior.attributes.get("rationale")
    if not desc:
        desc = f"Observed forensic network behavior classified as {behavior.behavior_type.replace('_', ' ')}."

    response_data = {
        "behavior_id": behavior.behavior_id,
        "case_id": behavior.case_id,
        "name": getattr(behavior, 'label', None) or behavior.behavior_type.replace('_', ' ').title(),
        "description": desc,
        "category": getattr(behavior, 'behavior_type', None) or "suspicious_activity",
        "severity": severity,
        "confidence": getattr(behavior, 'confidence', None),
        "first_observed": first_obs,
        "last_observed": last_obs,
        "associated_entities": [EntityResponse.model_validate(e) for e in detail["entities"]],
        "related_timeline_events": [TimelineEventResponse.model_validate(t) for t in detail["timeline_events"]],
        "related_findings": detail["findings"],
        "related_relationships": [RelationshipResponse.model_validate(r) for r in detail["relationships"]],
        "related_mitre_techniques": [MitreMappingResponse.model_validate(m) for m in detail["mitre_mappings"]],
    }
        
    return response_data

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

