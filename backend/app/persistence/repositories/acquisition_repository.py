from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from app.persistence.models.acquisition_models import AcquisitionModel, EvidenceModel

class AcquisitionRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, acquisition: AcquisitionModel) -> AcquisitionModel:
        self.session.add(acquisition)
        await self.session.flush()
        return acquisition

    async def get(self, acquisition_id: UUID) -> Optional[AcquisitionModel]:
        from sqlalchemy.orm import selectinload
        stmt = select(AcquisitionModel).options(selectinload(AcquisitionModel.evidence)).where(AcquisitionModel.acquisition_id == acquisition_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    get_by_id = get

    async def list_by_case(
        self,
        case_id: UUID,
        skip: int = 0,
        limit: int = 25,
        status: Optional[str] = None,
        format: Optional[str] = None
    ):
        from sqlalchemy import func
        from app.persistence.models.investigation_models import case_acquisition_links
        
        stmt = select(AcquisitionModel).join(
            case_acquisition_links, 
            AcquisitionModel.acquisition_id == case_acquisition_links.c.acquisition_id
        ).where(case_acquisition_links.c.case_id == case_id)
        
        if status:
            stmt = stmt.where(AcquisitionModel.status == status)
        if format:
            stmt = stmt.where(AcquisitionModel.format == format)
            
        stmt = stmt.order_by(AcquisitionModel.ingested_at.desc())
        
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.session.execute(count_stmt)).scalar() or 0
        
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all(), total

    async def link_to_case(self, case_id: UUID, acquisition_id: UUID) -> None:
        from app.persistence.models.investigation_models import case_acquisition_links
        from sqlalchemy.dialects.postgresql import insert
        
        stmt = insert(case_acquisition_links).values(
            case_id=case_id,
            acquisition_id=acquisition_id
        ).on_conflict_do_nothing()
        await self.session.execute(stmt)
        await self.session.flush()

class EvidenceRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, evidence: EvidenceModel) -> EvidenceModel:
        self.session.add(evidence)
        await self.session.flush()
        return evidence

    async def get(self, evidence_id: UUID) -> Optional[EvidenceModel]:
        from sqlalchemy.orm import joinedload
        stmt = select(EvidenceModel).options(joinedload(EvidenceModel.acquisition)).where(EvidenceModel.evidence_id == evidence_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(
        self,
        case_id: UUID,
        skip: int = 0,
        limit: int = 25
    ):
        from sqlalchemy import func
        from sqlalchemy.orm import joinedload
        from app.persistence.models.investigation_models import case_acquisition_links
        
        stmt = select(EvidenceModel).options(joinedload(EvidenceModel.acquisition)).join(
            AcquisitionModel, EvidenceModel.acquisition_id == AcquisitionModel.acquisition_id
        ).join(
            case_acquisition_links, AcquisitionModel.acquisition_id == case_acquisition_links.c.acquisition_id
        ).where(case_acquisition_links.c.case_id == case_id)
        
        stmt = stmt.order_by(EvidenceModel.registered_at.desc())
        
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = (await self.session.execute(count_stmt)).scalar() or 0
        
        stmt = stmt.offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return result.scalars().all(), total
