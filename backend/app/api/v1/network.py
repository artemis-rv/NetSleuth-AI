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
    ArtifactResponse, ArtifactListResponse,
    IPEntityListResponse,
    NetworkEndpointContextResponse, NetworkEndpointContextListResponse
)

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
    return await service.list_flows_by_case(
        case_id=case_id, page=page, page_size=page_size,
        src_ip=src_ip.strip() if src_ip and src_ip.strip() else None,
        dst_ip=dst_ip.strip() if dst_ip and dst_ip.strip() else None,
        protocol=protocol.strip() if protocol and protocol.strip() else None
    )

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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    await verify_case_access_direct(case_id, user, db)
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
    flow = await service.get_flow(flow_id)
    case_id = await service.get_case_id_for_acquisition(flow.acquisition_id)
    if not case_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    await verify_case_access_direct(case_id, user, db)
    return await service.list_events_by_flow(flow_id=flow_id, page=page, page_size=page_size)

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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    await verify_case_access_direct(case_id, user, db)
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
    return await service.list_artifacts_by_case(
        case_id=case_id, page=page, page_size=page_size,
        artifact_type=artifact_type.strip() if artifact_type and artifact_type.strip() else None
    )

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
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    await verify_case_access_direct(case_id, user, db)
    return artifact

@router.get(
    "/cases/{case_id}/network/entities",
    response_model=IPEntityListResponse,
    summary="List Contextual Network IP Entities by Case"
)
async def list_case_ip_entities(
    case_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: NetworkIntelligenceService = Depends(get_network_service)
):
    await verify_case_access_direct(case_id, user, db)
    return await service.list_ip_entities_by_case(case_id=case_id)

@router.get(
    "/cases/{case_id}/network/endpoints",
    response_model=NetworkEndpointContextListResponse,
    summary="List Dynamic Forensic Network Endpoint Contexts"
)
async def list_case_endpoint_contexts(
    case_id: UUID = Path(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    search_ip: Optional[str] = Query(None),
    protocol: Optional[str] = Query(None),
    service_param: Optional[str] = Query(None, alias="service"),
    port: Optional[str] = Query(None),
    network_scope: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    min_risk: Optional[str] = Query(None),
    min_anomaly: Optional[str] = Query(None),
    sort_by: Optional[str] = Query("risk_score"),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: NetworkIntelligenceService = Depends(get_network_service)
):
    await verify_case_access_direct(case_id, user, db)
    
    port_val = None
    if port and port.strip() and port.strip().isdigit():
        port_val = int(port.strip())
        
    risk_val = None
    if min_risk and min_risk.strip():
        try: risk_val = float(min_risk.strip())
        except ValueError: pass
        
    anomaly_val = None
    if min_anomaly and min_anomaly.strip():
        try: anomaly_val = float(min_anomaly.strip())
        except ValueError: pass

    return await service.list_endpoint_contexts_by_case(
        case_id=case_id,
        page=page,
        page_size=page_size,
        search_ip=search_ip.strip() if search_ip and search_ip.strip() else None,
        protocol=protocol.strip() if protocol and protocol.strip() else None,
        service=service_param.strip() if service_param and service_param.strip() else None,
        port=port_val,
        network_scope=network_scope.strip() if network_scope and network_scope.strip() else None,
        severity=severity.strip() if severity and severity.strip() else None,
        min_risk=risk_val,
        min_anomaly=anomaly_val,
        sort_by=sort_by.strip() if sort_by and sort_by.strip() else "risk_score"
    )

@router.get(
    "/cases/{case_id}/network/endpoints/{ip}",
    response_model=NetworkEndpointContextResponse,
    summary="Get Endpoint Forensic Context Detail"
)
async def get_endpoint_context_detail(
    case_id: UUID = Path(...),
    ip: str = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: NetworkIntelligenceService = Depends(get_network_service)
):
    await verify_case_access_direct(case_id, user, db)
    return await service.get_endpoint_context_detail(case_id=case_id, ip=ip.strip())
