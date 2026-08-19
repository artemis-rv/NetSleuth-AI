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

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 50) -> List[EntityModel]:
        stmt = select(EntityModel).where(EntityModel.case_id == case_id).order_by(EntityModel.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(EntityModel.entity_id)).where(EntityModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def get(self, entity_id: UUID) -> Optional[EntityModel]:
        stmt = select(EntityModel).where(EntityModel.entity_id == entity_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

class RelationshipRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, relationships: List[RelationshipModel]) -> None:
        self.session.add_all(relationships)
        await self.session.flush()

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 100) -> List[RelationshipModel]:
        stmt = select(RelationshipModel).where(RelationshipModel.case_id == case_id).order_by(RelationshipModel.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(RelationshipModel.relationship_id)).where(RelationshipModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def get(self, relationship_id: UUID) -> Optional[RelationshipModel]:
        stmt = select(RelationshipModel).where(RelationshipModel.relationship_id == relationship_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()

class BehaviorRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, behaviors: List[BehaviorModel]) -> None:
        self.session.add_all(behaviors)
        await self.session.flush()

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 50) -> List[BehaviorModel]:
        stmt = select(BehaviorModel).where(BehaviorModel.case_id == case_id).order_by(BehaviorModel.first_observed.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(BehaviorModel.behavior_id)).where(BehaviorModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

class TimelineEventRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, events: List[TimelineEventModel]) -> None:
        self.session.add_all(events)
        await self.session.flush()

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 50) -> List[TimelineEventModel]:
        stmt = select(TimelineEventModel).where(TimelineEventModel.case_id == case_id).order_by(TimelineEventModel.event_timestamp.asc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(TimelineEventModel.timeline_event_id)).where(TimelineEventModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

class MitreMappingRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, mappings: List[MitreMappingModel]) -> None:
        self.session.add_all(mappings)
        await self.session.flush()

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 50) -> List[MitreMappingModel]:
        stmt = select(MitreMappingModel).where(MitreMappingModel.case_id == case_id).order_by(MitreMappingModel.mapped_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(MitreMappingModel.mitre_mapping_id)).where(MitreMappingModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

from app.persistence.models.investigation_models import AttackChainModel

class AttackChainRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_case(self, case_id: UUID) -> Optional[AttackChainModel]:
        stmt = select(AttackChainModel).where(AttackChainModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()


# ─────────────────────────────────────────────
# V1.3 Assessment Repositories
# ─────────────────────────────────────────────

from app.persistence.models.investigation_models import (
    HypothesisModel, HypothesisValidationModel,
    RootCauseModel, ImpactAssessmentModel
)

class HypothesisRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, items: List[HypothesisModel]) -> None:
        self.session.add_all(items)
        await self.session.flush()

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 50) -> List[HypothesisModel]:
        stmt = select(HypothesisModel).where(HypothesisModel.case_id == case_id).order_by(HypothesisModel.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(HypothesisModel.hypothesis_id)).where(HypothesisModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def get(self, hypothesis_id: UUID) -> Optional[HypothesisModel]:
        stmt = select(HypothesisModel).where(HypothesisModel.hypothesis_id == hypothesis_id)
        result = await self.session.execute(stmt)
        return result.scalar_one_or_none()


class HypothesisValidationRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, items: List[HypothesisValidationModel]) -> None:
        self.session.add_all(items)
        await self.session.flush()

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 50) -> List[HypothesisValidationModel]:
        stmt = select(HypothesisValidationModel).where(HypothesisValidationModel.case_id == case_id).order_by(HypothesisValidationModel.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(HypothesisValidationModel.validation_id)).where(HypothesisValidationModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()

    async def list_by_hypothesis(self, hypothesis_id: UUID, skip: int = 0, limit: int = 50) -> List[HypothesisValidationModel]:
        stmt = select(HypothesisValidationModel).where(HypothesisValidationModel.hypothesis_id == hypothesis_id).order_by(HypothesisValidationModel.validated_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())


class RootCauseRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, items: List[RootCauseModel]) -> None:
        self.session.add_all(items)
        await self.session.flush()

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 50) -> List[RootCauseModel]:
        stmt = select(RootCauseModel).where(RootCauseModel.case_id == case_id).order_by(RootCauseModel.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(RootCauseModel.root_cause_id)).where(RootCauseModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()


class ImpactAssessmentRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def bulk_create(self, items: List[ImpactAssessmentModel]) -> None:
        self.session.add_all(items)
        await self.session.flush()

    async def list_by_case(self, case_id: UUID, skip: int = 0, limit: int = 50) -> List[ImpactAssessmentModel]:
        stmt = select(ImpactAssessmentModel).where(ImpactAssessmentModel.case_id == case_id).order_by(ImpactAssessmentModel.created_at.desc()).offset(skip).limit(limit)
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def count_by_case(self, case_id: UUID) -> int:
        from sqlalchemy import func
        stmt = select(func.count(ImpactAssessmentModel.impact_id)).where(ImpactAssessmentModel.case_id == case_id)
        result = await self.session.execute(stmt)
        return result.scalar_one()
