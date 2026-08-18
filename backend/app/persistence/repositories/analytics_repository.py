from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from uuid import UUID

from app.persistence.models.analytics_models import FindingsPackageModel, FindingModel, ModelRegistryModel

class FindingsPackageRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, package: FindingsPackageModel) -> FindingsPackageModel:
        self.session.add(package)
        await self.session.flush()
        return package

    async def get(self, package_id: UUID) -> Optional[FindingsPackageModel]:
        stmt = select(FindingsPackageModel).where(FindingsPackageModel.package_id == package_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

class FindingRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, findings: List[FindingModel]) -> None:
        self.session.add_all(findings)
        await self.session.flush()

    async def get(self, finding_id: UUID) -> Optional[FindingModel]:
        stmt = select(FindingModel).where(FindingModel.finding_id == finding_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def list_by_case(
        self,
        case_id: UUID,
        skip: int = 0,
        limit: int = 50,
        activity: Optional[str] = None,
        decision_state: Optional[str] = None,
        min_risk: Optional[float] = None
    ) -> List[FindingModel]:
        from app.persistence.models.investigation_models import case_acquisition_links
        
        stmt = select(FindingModel).join(
            case_acquisition_links,
            FindingModel.acquisition_id == case_acquisition_links.c.acquisition_id
        ).where(case_acquisition_links.c.case_id == case_id)
        
        if activity:
            stmt = stmt.where(FindingModel.activity == activity)
        if decision_state:
            stmt = stmt.where(FindingModel.decision_state == decision_state)
        if min_risk is not None:
            stmt = stmt.where(FindingModel.risk_score >= min_risk)
            
        stmt = stmt.order_by(FindingModel.detected_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())
        
    async def count_by_case(
        self,
        case_id: UUID,
        activity: Optional[str] = None,
        decision_state: Optional[str] = None,
        min_risk: Optional[float] = None
    ) -> int:
        from app.persistence.models.investigation_models import case_acquisition_links
        from sqlalchemy import func
        
        stmt = select(func.count(FindingModel.finding_id)).join(
            case_acquisition_links,
            FindingModel.acquisition_id == case_acquisition_links.c.acquisition_id
        ).where(case_acquisition_links.c.case_id == case_id)
        
        if activity:
            stmt = stmt.where(FindingModel.activity == activity)
        if decision_state:
            stmt = stmt.where(FindingModel.decision_state == decision_state)
        if min_risk is not None:
            stmt = stmt.where(FindingModel.risk_score >= min_risk)
            
        result = await self.session.execute(stmt)
        return result.scalar_one()

class ModelRegistryRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, registry: ModelRegistryModel) -> ModelRegistryModel:
        self.session.add(registry)
        await self.session.flush()
        return registry

    async def get(self, model_id: UUID) -> Optional[ModelRegistryModel]:
        stmt = select(ModelRegistryModel).where(ModelRegistryModel.model_id == model_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()
