from typing import Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from uuid import UUID

from app.persistence.models.investigation_models import (
    InvestigationCaseModel, EntityModel, RelationshipModel, 
    BehaviorModel, TimelineEventModel, MitreMappingModel
)

class InvestigationCaseRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, case: InvestigationCaseModel) -> InvestigationCaseModel:
        self.session.add(case)
        await self.session.flush()
        return case

    async def get(self, case_id: UUID) -> Optional[InvestigationCaseModel]:
        stmt = select(InvestigationCaseModel).where(InvestigationCaseModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

    async def update_status(self, case_id: UUID, new_status: str) -> Optional[InvestigationCaseModel]:
        stmt = update(InvestigationCaseModel).where(InvestigationCaseModel.case_id == case_id).values(status=new_status).returning(InvestigationCaseModel)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.scalar_one_or_none()

class EntityRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, entities: List[EntityModel]) -> None:
        self.session.add_all(entities)
        await self.session.flush()

class RelationshipRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, relationships: List[RelationshipModel]) -> None:
        self.session.add_all(relationships)
        await self.session.flush()

class BehaviorRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, behaviors: List[BehaviorModel]) -> None:
        self.session.add_all(behaviors)
        await self.session.flush()

class TimelineEventRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, events: List[TimelineEventModel]) -> None:
        self.session.add_all(events)
        await self.session.flush()

class MitreMappingRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, mappings: List[MitreMappingModel]) -> None:
        self.session.add_all(mappings)
        await self.session.flush()
