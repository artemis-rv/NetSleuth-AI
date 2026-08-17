from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from app.persistence.models.custody_models import EvidenceItemModel, CustodyEventModel, ReportModel

class EvidenceItemRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, item: EvidenceItemModel) -> EvidenceItemModel:
        self.session.add(item)
        await self.session.flush()
        return item

    async def get(self, item_id: UUID) -> Optional[EvidenceItemModel]:
        stmt = select(EvidenceItemModel).where(EvidenceItemModel.item_id == item_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

class CustodyEventRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, event: CustodyEventModel) -> CustodyEventModel:
        self.session.add(event)
        await self.session.flush()
        return event

class ReportRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, report: ReportModel) -> ReportModel:
        self.session.add(report)
        await self.session.flush()
        return report
