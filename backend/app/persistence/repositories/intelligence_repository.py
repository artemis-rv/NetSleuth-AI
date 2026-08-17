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
