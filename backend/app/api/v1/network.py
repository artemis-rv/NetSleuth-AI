from fastapi import APIRouter, Depends, Query, status, Path, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID
from typing import Optional

from app.auth.dependencies import get_current_user, verify_case_access_direct, get_db
from app.persistence.models.identity_models import UserModel
from app.services.network_service import NetworkIntelligenceService
from app.contracts.api.network import (
    FlowDetailResponse, FlowListResponse,
    ProtocolEventResponse, ProtocolEventListResponse,
    ArtifactResponse, ArtifactListResponse
)
from app.services.audit_service import log_audit_event

router = APIRouter(tags=["Network Intelligence"])

def get_network_service(db: AsyncSession = Depends(get_db)) -> NetworkIntelligenceService:
    return NetworkIntelligenceService(db)

@router.get(
    "/cases/{case_id}/flows",
    response_model=FlowListResponse,
    summary="List Network Flows by Case"
)
async def list_case_flows(
    case_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    src_ip: Optional[str] = Query(None),
    dst_ip: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: NetworkIntelligenceService = Depends(get_network_service)
):
    await verify_case_access_direct(case_id, user, db)
    
    response = await service.list_flows_by_case(
        case_id=case_id, page=page, page_size=page_size,
        src_ip=src_ip, dst_ip=dst_ip, protocol=protocol
    )
    return response

@router.get(
    "/flows/{flow_id}",
    response_model=FlowDetailResponse,
    summary="Get Flow Detail"
)
async def get_flow(
    flow_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: NetworkIntelligenceService = Depends(get_network_service)
):
    flow = await service.get_flow(flow_id)
    case_id = await service.get_case_id_for_acquisition(flow.acquisition_id)
    
    if not case_id:
        await log_audit_event(db, "UNAUTHORIZED_FLOW_ACCESS", user.user_id, str(flow_id), "Flow not linked to a case")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
    try:
        await verify_case_access_direct(case_id, user, db)
    except Exception as e:
        await log_audit_event(db, "UNAUTHORIZED_FLOW_ACCESS", user.user_id, str(flow_id), "User lacks access to flow's case")
        raise e
        
    await log_audit_event(db, "FLOW_VIEWED", user.user_id, str(flow_id))
    return flow

@router.get(
    "/flows/{flow_id}/events",
    response_model=ProtocolEventListResponse,
    summary="List Events by Flow"
)
async def list_flow_events(
    flow_id: UUID = Path(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: NetworkIntelligenceService = Depends(get_network_service)
):
    # Verify access to the flow first
    flow = await service.get_flow(flow_id)
    case_id = await service.get_case_id_for_acquisition(flow.acquisition_id)
    
    if not case_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
    await verify_case_access_direct(case_id, user, db)
    
    response = await service.list_events_by_flow(flow_id=flow_id, page=page, page_size=page_size)
    return response

@router.get(
    "/events/{event_id}",
    response_model=ProtocolEventResponse,
    summary="Get Event Detail"
)
async def get_event(
    event_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: NetworkIntelligenceService = Depends(get_network_service)
):
    event = await service.get_event(event_id)
    case_id = await service.get_case_id_for_acquisition(event.acquisition_id)
    
    if not case_id:
        await log_audit_event(db, "UNAUTHORIZED_EVENT_ACCESS", user.user_id, str(event_id), "Event not linked to a case")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
    try:
        await verify_case_access_direct(case_id, user, db)
    except Exception as e:
        await log_audit_event(db, "UNAUTHORIZED_EVENT_ACCESS", user.user_id, str(event_id), "User lacks access to event's case")
        raise e
        
    await log_audit_event(db, "EVENT_VIEWED", user.user_id, str(event_id))
    return event

@router.get(
    "/cases/{case_id}/artifacts",
    response_model=ArtifactListResponse,
    summary="List Artifacts by Case"
)
async def list_case_artifacts(
    case_id: UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    artifact_type: Optional[str] = Query(None),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: NetworkIntelligenceService = Depends(get_network_service)
):
    await verify_case_access_direct(case_id, user, db)
    
    response = await service.list_artifacts_by_case(
        case_id=case_id, page=page, page_size=page_size, artifact_type=artifact_type
    )
    return response

@router.get(
    "/artifacts/{artifact_id}",
    response_model=ArtifactResponse,
    summary="Get Artifact Detail"
)
async def get_artifact(
    artifact_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: NetworkIntelligenceService = Depends(get_network_service)
):
    artifact = await service.get_artifact(artifact_id)
    case_id = await service.get_case_id_for_acquisition(artifact.acquisition_id)
    
    if not case_id:
        await log_audit_event(db, "UNAUTHORIZED_ARTIFACT_ACCESS", user.user_id, str(artifact_id), "Artifact not linked to a case")
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
        
    try:
        await verify_case_access_direct(case_id, user, db)
    except Exception as e:
        await log_audit_event(db, "UNAUTHORIZED_ARTIFACT_ACCESS", user.user_id, str(artifact_id), "User lacks access to artifact's case")
        raise e
        
    await log_audit_event(db, "ARTIFACT_VIEWED", user.user_id, str(artifact_id))
    return artifact
