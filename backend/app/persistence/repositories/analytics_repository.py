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
