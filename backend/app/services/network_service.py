from uuid import UUID
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.persistence.repositories.intelligence_repository import FlowRepository, ProtocolEventRepository, ArtifactRepository
from app.contracts.api.network import (
    FlowDetailResponse, FlowListResponse, FlowListItem,
    ProtocolEventResponse, ProtocolEventListResponse,
    ArtifactResponse, ArtifactListResponse
)

class NetworkIntelligenceService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.flow_repo = FlowRepository(db)
        self.event_repo = ProtocolEventRepository(db)
        self.artifact_repo = ArtifactRepository(db)

    async def list_flows_by_case(
        self,
        case_id: UUID,
        page: int,
        page_size: int,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None
    ) -> FlowListResponse:
        
        skip = (page - 1) * page_size
        flows = await self.flow_repo.list_by_case(
            case_id=case_id,
            skip=skip,
            limit=page_size,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol
        )
        total = await self.flow_repo.count_by_case(
            case_id=case_id,
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol=protocol
        )

        return FlowListResponse(
            items=[FlowListItem.model_validate(f) for f in flows],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_flow(self, flow_id: UUID) -> FlowDetailResponse:
        flow = await self.flow_repo.get(flow_id)
        if not flow:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Flow not found")
        return FlowDetailResponse.model_validate(flow)

    async def list_events_by_flow(self, flow_id: UUID, page: int, page_size: int) -> ProtocolEventListResponse:
        skip = (page - 1) * page_size
        events = await self.event_repo.list_by_flow(flow_id=flow_id, skip=skip, limit=page_size)
        total = await self.event_repo.count_by_flow(flow_id=flow_id)
        
        return ProtocolEventListResponse(
            items=[ProtocolEventResponse.model_validate(e) for e in events],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_event(self, event_id: UUID) -> ProtocolEventResponse:
        event = await self.event_repo.get(event_id)
        if not event:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
        return ProtocolEventResponse.model_validate(event)

    async def list_artifacts_by_case(
        self,
        case_id: UUID,
        page: int,
        page_size: int,
        artifact_type: Optional[str] = None
    ) -> ArtifactListResponse:
        skip = (page - 1) * page_size
        artifacts = await self.artifact_repo.list_by_case(
            case_id=case_id,
            skip=skip,
            limit=page_size,
            artifact_type=artifact_type
        )
        total = await self.artifact_repo.count_by_case(case_id=case_id, artifact_type=artifact_type)
        
        return ArtifactListResponse(
            items=[ArtifactResponse.model_validate(a) for a in artifacts],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_artifact(self, artifact_id: UUID) -> ArtifactResponse:
        artifact = await self.artifact_repo.get(artifact_id)
        if not artifact:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Artifact not found")
        return ArtifactResponse.model_validate(artifact)

    async def get_case_id_for_acquisition(self, acquisition_id: UUID) -> Optional[UUID]:
        from app.persistence.models.investigation_models import case_acquisition_links
        from sqlalchemy import select
        
        stmt = select(case_acquisition_links.c.case_id).where(case_acquisition_links.c.acquisition_id == acquisition_id)
        result = await self.db.execute(stmt)
        row = result.first()
        if row:
            return row[0]
        return None
