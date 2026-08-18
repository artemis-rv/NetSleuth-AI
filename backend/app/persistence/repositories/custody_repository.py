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

    async def get(self, evidence_item_id: UUID) -> Optional[EvidenceItemModel]:
        stmt = select(EvidenceItemModel).where(EvidenceItemModel.evidence_item_id == evidence_item_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 50) -> List[EvidenceItemModel]:
        stmt = select(EvidenceItemModel).where(EvidenceItemModel.case_id == case_id).order_by(EvidenceItemModel.registered_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(EvidenceItemModel.evidence_item_id)).where(EvidenceItemModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

class CustodyEventRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, event: CustodyEventModel) -> CustodyEventModel:
        self.session.add(event)
        await self.session.flush()
        return event

    async def list_by_item(self, evidence_item_id: UUID, skip: int = 0, limit: int = 50) -> List[CustodyEventModel]:
        stmt = select(CustodyEventModel).where(CustodyEventModel.evidence_item_id == evidence_item_id).order_by(CustodyEventModel.occurred_at.asc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_item(self, evidence_item_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(CustodyEventModel.custody_event_id)).where(CustodyEventModel.evidence_item_id == evidence_item_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

class ReportRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, report: ReportModel) -> ReportModel:
        self.session.add(report)
        await self.session.flush()
        return report

    async def get(self, report_id: UUID) -> Optional[ReportModel]:
        stmt = select(ReportModel).where(ReportModel.report_id == report_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 50) -> List[ReportModel]:
        stmt = select(ReportModel).where(ReportModel.case_id == case_id).order_by(ReportModel.generated_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(ReportModel.report_id)).where(ReportModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()
