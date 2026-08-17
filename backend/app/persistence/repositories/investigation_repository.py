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

    async def update(self, case_id: UUID, update_data: dict) -> Optional[InvestigationCaseModel]:
        if not update_data:
            return await self.get(case_id)
        stmt = update(InvestigationCaseModel).where(InvestigationCaseModel.case_id == case_id).values(**update_data).returning(InvestigationCaseModel)
        result = await self.session.execute(stmt)
        await self.session.flush()
        return result.scalar_one_or_none()

    async def list_cases(
        self, 
        user_id: UUID, 
        role: str, 
        skip: int = 0, 
        limit: int = 25,
        status: Optional[str] = None,
        priority: Optional[str] = None,
        sort_by: str = "created_at",
        sort_desc: bool = True
    ):
        from sqlalchemy import func
        from app.persistence.models.identity_models import CaseAccessModel
        
        # Base query
        stmt = select(InvestigationCaseModel)
        
        # Apply RBAC
        if role != "administrator":
            stmt = stmt.join(CaseAccessModel, InvestigationCaseModel.case_id == CaseAccessModel.case_id)
            stmt = stmt.where(CaseAccessModel.user_id == user_id)
            
        # Apply filters
        if status:
            stmt = stmt.where(InvestigationCaseModel.status == status)
        if priority:
            stmt = stmt.where(InvestigationCaseModel.priority == priority)
            
        # Apply sorting
        order_col = InvestigationCaseModel.opened_at if sort_by == "created_at" else getattr(InvestigationCaseModel, sort_by, InvestigationCaseModel.opened_at)
        if sort_desc:
            stmt = stmt.order_by(order_col.desc())
        else:
            stmt = stmt.order_by(order_col.asc())
            
        # Get total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total_result = await self.session.execute(count_stmt)
        total = total_result.scalar() or 0
        
        # Apply pagination
        stmt = stmt.offset(skip).limit(limit)
        
        result = await self.session.execute(stmt)
        items = result.scalars().all()
        
        return items, total

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
