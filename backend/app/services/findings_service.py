from uuid import UUID
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.persistence.repositories.analytics_repository import FindingRepository
from app.contracts.api.findings import FindingDetailResponse, FindingListResponse, FindingListItem

class FindingsService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.repository = FindingRepository(db)

    async def list_findings_by_case(
        self,
        case_id: UUID,
        page: int,
        page_size: int,
        activity: Optional[str] = None,
        decision_state: Optional[str] = None,
        min_risk: Optional[float] = None
    ) -> FindingListResponse:
        
        skip = (page - 1) * page_size
        findings = await self.repository.list_by_case(
            case_id=case_id,
            skip=skip,
            limit=page_size,
            activity=activity,
            decision_state=decision_state,
            min_risk=min_risk
        )
        total = await self.repository.count_by_case(
            case_id=case_id,
            activity=activity,
            decision_state=decision_state,
            min_risk=min_risk
        )

        return FindingListResponse(
            items=[FindingListItem.model_validate(f) for f in findings],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_finding(self, finding_id: UUID) -> FindingDetailResponse:
        finding = await self.repository.get(finding_id)
        if not finding:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Finding not found")
        return FindingDetailResponse.model_validate(finding)
        
    async def get_case_id_for_acquisition(self, acquisition_id: UUID) -> Optional[UUID]:
        from app.persistence.models.investigation_models import case_acquisition_links
        from sqlalchemy import select
        
        stmt = select(case_acquisition_links.c.case_id).where(case_acquisition_links.c.acquisition_id == acquisition_id)
        result = await self.db.execute(stmt)
        row = result.first()
        if row:
            return row[0]
        return None
