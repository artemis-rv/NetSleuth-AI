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
        stmt = select(AcquisitionModel).where(AcquisitionModel.acquisition_id == acquisition_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

class EvidenceRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, evidence: EvidenceModel) -> EvidenceModel:
        self.session.add(evidence)
        await self.session.flush()
        return evidence

    async def get(self, evidence_id: UUID) -> Optional[EvidenceModel]:
        stmt = select(EvidenceModel).where(EvidenceModel.evidence_id == evidence_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
