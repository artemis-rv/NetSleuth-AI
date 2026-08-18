from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.persistence.repositories.custody_repository import EvidenceItemRepository, CustodyEventRepository
from app.contracts.api.custody import (
    EvidenceItemListResponse, EvidenceItemResponse,
    CustodyEventListResponse, CustodyEventResponse
)

class CustodyService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.item_repo = EvidenceItemRepository(db)
        self.event_repo = CustodyEventRepository(db)

    async def list_items_by_case(self, case_id: UUID, page: int, page_size: int) -> EvidenceItemListResponse:
        skip = (page - 1) * page_size
        items = await self.item_repo.list_by_case(case_id=case_id, skip=skip, limit=page_size)
        total = await self.item_repo.count_by_case(case_id=case_id)
        
        return EvidenceItemListResponse(
            items=[EvidenceItemResponse.model_validate(i) for i in items],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_item(self, item_id: UUID) -> EvidenceItemResponse:
        item = await self.item_repo.get(item_id)
        if not item:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found")
        return EvidenceItemResponse.model_validate(item)

    async def list_events_by_item(self, item_id: UUID, page: int, page_size: int) -> CustodyEventListResponse:
        skip = (page - 1) * page_size
        
        # Verify item exists first
        item = await self.item_repo.get(item_id)
        if not item:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Evidence item not found")
            
        events = await self.event_repo.list_by_item(evidence_item_id=item_id, skip=skip, limit=page_size)
        total = await self.event_repo.count_by_item(evidence_item_id=item_id)
        
        return CustodyEventListResponse(
            items=[CustodyEventResponse.model_validate(e) for e in events],
            total=total,
            page=page,
            page_size=page_size
        )
