from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from app.persistence.models.intelligence_models import FlowModel, ProtocolEventModel, ArtifactModel

class FlowRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, flows: List[FlowModel]) -> None:
        self.session.add_all(flows)
        await self.session.flush()

    async def get(self, flow_id: UUID) -> Optional[FlowModel]:
        stmt = select(FlowModel).where(FlowModel.flow_id == flow_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(
        self,
        case_id: UUID,
        skip: int = 0,
        limit: int = 50,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None
    ) -> List[FlowModel]:
        from app.persistence.models.investigation_models import case_acquisition_links
        
        stmt = select(FlowModel).join(
            case_acquisition_links,
            FlowModel.acquisition_id == case_acquisition_links.c.acquisition_id
        ).where(case_acquisition_links.c.case_id == case_id)
        
        if src_ip:
            stmt = stmt.where(FlowModel.src_ip == src_ip)
        if dst_ip:
            stmt = stmt.where(FlowModel.dst_ip == dst_ip)
        if protocol:
            stmt = stmt.where(FlowModel.protocol == protocol)
            
        stmt = stmt.order_by(FlowModel.timestamp.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(
        self,
        case_id: UUID,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        protocol: Optional[str] = None
    ) -> int:
        from app.persistence.models.investigation_models import case_acquisition_links
        from sqlalchemy import func
        
        stmt = select(func.count(FlowModel.flow_id)).join(
            case_acquisition_links,
            FlowModel.acquisition_id == case_acquisition_links.c.acquisition_id
        ).where(case_acquisition_links.c.case_id == case_id)
        
        if src_ip:
            stmt = stmt.where(FlowModel.src_ip == src_ip)
        if dst_ip:
            stmt = stmt.where(FlowModel.dst_ip == dst_ip)
        if protocol:
            stmt = stmt.where(FlowModel.protocol == protocol)
            
        result = await self.session.execute(stmt)
        return result.scalar_one()

class ProtocolEventRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, events: List[ProtocolEventModel]) -> None:
        self.session.add_all(events)
        await self.session.flush()

    async def get(self, event_id: UUID) -> Optional[ProtocolEventModel]:
        stmt = select(ProtocolEventModel).where(ProtocolEventModel.event_id == event_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_flow(
        self,
        flow_id: UUID,
        skip: int = 0,
        limit: int = 50
    ) -> List[ProtocolEventModel]:
        stmt = select(ProtocolEventModel).where(ProtocolEventModel.flow_id == flow_id)
        stmt = stmt.order_by(ProtocolEventModel.timestamp.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_flow(
        self,
        flow_id: UUID
    ) -> int:
        from sqlalchemy import func
        stmt = select(func.count(ProtocolEventModel.event_id)).where(ProtocolEventModel.flow_id == flow_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

class ArtifactRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, artifacts: List[ArtifactModel]) -> None:
        self.session.add_all(artifacts)
        await self.session.flush()

    async def get(self, artifact_id: UUID) -> Optional[ArtifactModel]:
        stmt = select(ArtifactModel).where(ArtifactModel.artifact_id == artifact_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(
        self,
        case_id: UUID,
        skip: int = 0,
        limit: int = 50,
        artifact_type: Optional[str] = None
    ) -> List[ArtifactModel]:
        from app.persistence.models.investigation_models import case_acquisition_links
        
        stmt = select(ArtifactModel).join(
            case_acquisition_links,
            ArtifactModel.acquisition_id == case_acquisition_links.c.acquisition_id
        ).where(case_acquisition_links.c.case_id == case_id)
        
        if artifact_type:
            stmt = stmt.where(ArtifactModel.type == artifact_type)
            
        stmt = stmt.order_by(ArtifactModel.first_seen.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(
        self,
        case_id: UUID,
        artifact_type: Optional[str] = None
    ) -> int:
        from app.persistence.models.investigation_models import case_acquisition_links
        from sqlalchemy import func
        
        stmt = select(func.count(ArtifactModel.artifact_id)).join(
            case_acquisition_links,
            ArtifactModel.acquisition_id == case_acquisition_links.c.acquisition_id
        ).where(case_acquisition_links.c.case_id == case_id)
        
        if artifact_type:
            stmt = stmt.where(ArtifactModel.type == artifact_type)
            
        result = await self.session.execute(stmt)
        return result.scalar_one()
