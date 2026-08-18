from uuid import UUID
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.persistence.repositories.custody_repository import ReportRepository
from app.contracts.api.reports import ReportListResponse, ReportResponse

class ReportsService:
    def __init__(self, db: AsyncSession):
        self.db = db
        self.report_repo = ReportRepository(db)

    async def list_reports_by_case(self, case_id: UUID, page: int, page_size: int) -> ReportListResponse:
        skip = (page - 1) * page_size
        reports = await self.report_repo.list_by_case(case_id=case_id, skip=skip, limit=page_size)
        total = await self.report_repo.count_by_case(case_id=case_id)
        
        return ReportListResponse(
            items=[ReportResponse.model_validate(r) for r in reports],
            total=total,
            page=page,
            page_size=page_size
        )

    async def get_report(self, report_id: UUID) -> ReportResponse:
        report = await self.report_repo.get(report_id)
        if not report:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
        return ReportResponse.model_validate(report)
