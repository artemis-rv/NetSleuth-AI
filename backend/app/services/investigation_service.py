from uuid import UUID
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.persistence.repositories.investigation_repository import (
    EntityRepository, RelationshipRepository, BehaviorRepository,
    TimelineEventRepository, MitreMappingRepository, AttackChainRepository
)
from app.contracts.api.investigation import (
    EntityListResponse, EntityResponse,
    RelationshipListResponse, RelationshipResponse,
    BehaviorListResponse, BehaviorResponse,
    TimelineEventListResponse, TimelineEventResponse,
    MitreMappingListResponse, MitreMappingResponse,
    AttackChainResponse, GraphResponse
)

class InvestigationService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.entity_repo = EntityRepository(db)
        self.relationship_repo = RelationshipRepository(db)
        self.behavior_repo = BehaviorRepository(db)
        self.timeline_repo = TimelineEventRepository(db)
        self.mitre_repo = MitreMappingRepository(db)
        self.attack_chain_repo = AttackChainRepository(db)

    async def list_entities_by_case(self, case_id: UUID, page: int, page_size: int) -> EntityListResponse:
        skip = (page - 1) * page_size
        entities = await self.entity_repo.list_by_case(case_id=case_id, skip=skip, limit=page_size)
        total = await self.entity_repo.count_by_case(case_id=case_id)
        
        return EntityListResponse(
            items=[EntityResponse.model_validate(e) for e in entities],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_entity(self, entity_id: UUID) -> EntityResponse:
        entity = await self.entity_repo.get(entity_id)
        if not entity:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Entity not found")
        return EntityResponse.model_validate(entity)

    async def list_relationships_by_case(self, case_id: UUID, page: int, page_size: int) -> RelationshipListResponse:
        skip = (page - 1) * page_size
        relationships = await self.relationship_repo.list_by_case(case_id=case_id, skip=skip, limit=page_size)
        total = await self.relationship_repo.count_by_case(case_id=case_id)
        
        return RelationshipListResponse(
            items=[RelationshipResponse.model_validate(r) for r in relationships],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_relationship(self, relationship_id: UUID) -> RelationshipResponse:
        relationship = await self.relationship_repo.get(relationship_id)
        if not relationship:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Relationship not found")
        return RelationshipResponse.model_validate(relationship)

    async def list_behaviors_by_case(self, case_id: UUID, page: int, page_size: int) -> BehaviorListResponse:
        skip = (page - 1) * page_size
        behaviors = await self.behavior_repo.list_by_case(case_id=case_id, skip=skip, limit=page_size)
        total = await self.behavior_repo.count_by_case(case_id=case_id)
        
        return BehaviorListResponse(
            items=[BehaviorResponse.model_validate(b) for b in behaviors],
            total=total,
            page=page,
            page_size=page_size
        )

    async def list_timeline_by_case(self, case_id: UUID, page: int, page_size: int) -> TimelineEventListResponse:
        skip = (page - 1) * page_size
        events = await self.timeline_repo.list_by_case(case_id=case_id, skip=skip, limit=page_size)
        total = await self.timeline_repo.count_by_case(case_id=case_id)
        
        return TimelineEventListResponse(
            items=[TimelineEventResponse.model_validate(e) for e in events],
            total=total,
            page=page,
            page_size=page_size
        )

    async def list_mitre_mappings_by_case(self, case_id: UUID, page: int, page_size: int) -> MitreMappingListResponse:
        skip = (page - 1) * page_size
        mappings = await self.mitre_repo.list_by_case(case_id=case_id, skip=skip, limit=page_size)
        total = await self.mitre_repo.count_by_case(case_id=case_id)
        
        return MitreMappingListResponse(
            items=[MitreMappingResponse.model_validate(m) for m in mappings],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_attack_chain_by_case(self, case_id: UUID) -> AttackChainResponse:
        attack_chain = await self.attack_chain_repo.get_by_case(case_id)
        if not attack_chain:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Attack chain not found for this case")
        return AttackChainResponse.model_validate(attack_chain)

    async def get_graph_by_case(self, case_id: UUID) -> GraphResponse:
        entities = await self.entity_repo.list_by_case(case_id=case_id, skip=0, limit=1000)
        relationships = await self.relationship_repo.list_by_case(case_id=case_id, skip=0, limit=1000)
        
        return GraphResponse(
            nodes=[EntityResponse.model_validate(e) for e in entities],
            edges=[RelationshipResponse.model_validate(r) for r in relationships]
        )
