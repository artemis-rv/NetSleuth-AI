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

    async def get_detail_with_relations(self, behavior_id: UUID) -> Optional[dict]:
        from app.persistence.models.investigation_models import (
            TimelineEventModel, MitreMappingModel, RelationshipModel, EntityModel,
            behavior_finding_links, mitre_finding_links, relationship_finding_links
        )
        
        # 1. Get Behavior
        stmt_b = select(BehaviorModel).where(BehaviorModel.behavior_id == behavior_id)
        result_b = await self.session.execute(stmt_b)
        behavior = result_b.scalar_one_or_none()
        if not behavior:
            return None
            
        # 2. Get Timeline Events
        stmt_t = select(TimelineEventModel).where(TimelineEventModel.behavior_id == behavior_id).order_by(TimelineEventModel.event_timestamp.asc())
        result_t = await self.session.execute(stmt_t)
        timeline_events = list(result_t.scalars().all())
        
        # 3. Get related Finding IDs
        stmt_f = select(behavior_finding_links.c.finding_id).where(behavior_finding_links.c.behavior_id == behavior_id)
        result_f = await self.session.execute(stmt_f)
        finding_ids = [row[0] for row in result_f.all()]
        
        mitre_mappings = []
        relationships = []
        entities = []
        
        if finding_ids:
            # 4. Get MITRE by finding links
            stmt_m = select(MitreMappingModel).join(
                mitre_finding_links, MitreMappingModel.mitre_mapping_id == mitre_finding_links.c.mitre_mapping_id
            ).where(mitre_finding_links.c.finding_id.in_(finding_ids))
            mitre_mappings = list((await self.session.execute(stmt_m)).scalars().all())
            
            # 5. Get Relationships by finding links
            stmt_r = select(RelationshipModel).join(
                relationship_finding_links, RelationshipModel.relationship_id == relationship_finding_links.c.relationship_id
            ).where(relationship_finding_links.c.finding_id.in_(finding_ids))
            relationships = list((await self.session.execute(stmt_r)).scalars().all())

        # Fallbacks to case-scoped records if explicit link tables have not yet populated
        if not mitre_mappings and behavior.case_id:
            stmt_m_fallback = select(MitreMappingModel).where(MitreMappingModel.case_id == behavior.case_id)
            mitre_mappings = list((await self.session.execute(stmt_m_fallback)).scalars().all())
            
        if not relationships and behavior.case_id:
            stmt_r_fallback = select(RelationshipModel).where(RelationshipModel.case_id == behavior.case_id).limit(20)
            relationships = list((await self.session.execute(stmt_r_fallback)).scalars().all())
            
        # 6. Get Entities (from timeline, relationships, or case)
        entity_ids = set()
        for t in timeline_events:
            if getattr(t, 'entity_id', None): entity_ids.add(t.entity_id)
        for r in relationships:
            entity_ids.add(r.source_entity_id)
            entity_ids.add(r.target_entity_id)
            
        if entity_ids:
            stmt_e = select(EntityModel).where(EntityModel.entity_id.in_(list(entity_ids)))
            entities = list((await self.session.execute(stmt_e)).scalars().all())
        elif behavior.case_id:
            stmt_e_case = select(EntityModel).where(EntityModel.case_id == behavior.case_id).limit(20)
            entities = list((await self.session.execute(stmt_e_case)).scalars().all())
            
        return {
            "behavior": behavior,
            "timeline_events": timeline_events,
            "mitre_mappings": mitre_mappings,
            "relationships": relationships,
            "entities": entities,
            "findings": [behavior.attributes] if behavior.attributes else []
        }

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
