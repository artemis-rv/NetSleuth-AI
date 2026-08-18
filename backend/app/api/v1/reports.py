from fastapi import APIRouter, Depends, Query, Path, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from uuid import UUID

from app.auth.dependencies import get_current_user, verify_case_access_direct, get_db
from app.persistence.models.identity_models import UserModel
from app.services.reports_service import ReportsService
from app.contracts.api.reports import ReportListResponse, ReportResponse
from app.services.audit_service import log_audit_event

router = APIRouter(prefix="/reports", tags=["Reports"])

def get_reports_service(db: AsyncSession = Depends(get_db)) -> ReportsService:
    return ReportsService(db)

@router.get("/cases/{case_id}/reports", response_model=ReportListResponse)
async def list_case_reports(
    case_id: UUID = Path(...),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=100),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: ReportsService = Depends(get_reports_service)
):
    await verify_case_access_direct(case_id, user, db)
    return await service.list_reports_by_case(case_id=case_id, page=page, page_size=page_size)

@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: ReportsService = Depends(get_reports_service)
):
    report = await service.get_report(report_id)
    if not report:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Report not found")
        
    try:
        await verify_case_access_direct(report.case_id, user, db)
    except Exception as e:
        await log_audit_event(db, "UNAUTHORIZED_REPORT_ACCESS", user.user_id, str(report_id), "User lacks access to report's case")
        raise e
        
    return report
