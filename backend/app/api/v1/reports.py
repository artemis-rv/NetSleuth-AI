from fastapi import APIRouter, Depends, Query, Path, Request, Response
from fastapi.responses import Response as FastAPIResponse
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID

from app.auth.dependencies import get_current_user, verify_case_access_direct, get_db
from app.persistence.models.identity_models import UserModel
from app.services.reports_service import ReportsService
from app.contracts.api.reports import ReportListResponse, ReportResponse, GenerateReportRequest
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

@router.post("/cases/{case_id}/reports/generate", response_model=ReportResponse)
async def generate_report(
    payload: GenerateReportRequest,
    case_id: UUID = Path(...),
    request: Request = None,
    user: UserModel = Depends(get_current_user),
    service: ReportsService = Depends(get_reports_service)
):
    return await service.generate_report(
        case_id=case_id,
        current_user=user,
        format=payload.format,
        title=payload.title,
        http_request=request
    )

@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(
    report_id: UUID = Path(...),
    user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
    service: ReportsService = Depends(get_reports_service)
):
    report = await service.get_report(report_id)
    try:
        await verify_case_access_direct(report.case_id, user, db)
    except Exception as e:
        await log_audit_event(
            db=db,
            action="UNAUTHORIZED_REPORT_ACCESS",
            target_entity_type="report",
            target_entity_id=str(report_id),
            result="failure",
            actor_id=user.user_id,
            metadata={"reason": "User lacks access to report's case"}
        )
        raise e
        
    return report

@router.post("/{report_id}/finalize", response_model=ReportResponse)
async def finalize_report(
    report_id: UUID = Path(...),
    request: Request = None,
    user: UserModel = Depends(get_current_user),
    service: ReportsService = Depends(get_reports_service)
):
    return await service.finalize_report(
        report_id=report_id,
        current_user=user,
        http_request=request
    )

@router.get("/cases/{case_id}/reports/{report_id}/pdf")
async def get_case_report_pdf(
    case_id: UUID = Path(...),
    report_id: UUID = Path(...),
    request: Request = None,
    user: UserModel = Depends(get_current_user),
    service: ReportsService = Depends(get_reports_service)
):
    artifact_bytes, media_type, filename = await service.export_report(
        report_id=report_id,
        current_user=user,
        export_format="pdf",
        case_id=case_id,
        http_request=request
    )
    safe_filename = filename.encode('ascii', 'ignore').decode('ascii').replace(' ', '_')
    if not safe_filename or safe_filename.startswith('.'):
        safe_filename = f"Investigation_Report_{case_id}.pdf"

    headers = {
        "Content-Disposition": f'inline; filename="{safe_filename}"'
    }
    return FastAPIResponse(content=artifact_bytes, media_type="application/pdf", headers=headers)

@router.get("/{report_id}/pdf")
async def get_report_pdf(
    report_id: UUID = Path(...),
    request: Request = None,
    user: UserModel = Depends(get_current_user),
    service: ReportsService = Depends(get_reports_service)
):
    artifact_bytes, media_type, filename = await service.export_report(
        report_id=report_id,
        current_user=user,
        export_format="pdf",
        http_request=request
    )
    safe_filename = filename.encode('ascii', 'ignore').decode('ascii').replace(' ', '_')
    if not safe_filename or safe_filename.startswith('.'):
        safe_filename = f"Investigation_Report_{report_id}.pdf"

    headers = {
        "Content-Disposition": f'inline; filename="{safe_filename}"'
    }
    return FastAPIResponse(content=artifact_bytes, media_type="application/pdf", headers=headers)

@router.get("/{report_id}/export")
async def export_report(
    report_id: UUID = Path(...),
    format: Optional[str] = Query(None),
    case_id: Optional[UUID] = Query(None),
    request: Request = None,
    user: UserModel = Depends(get_current_user),
    service: ReportsService = Depends(get_reports_service)
):
    artifact_bytes, media_type, filename = await service.export_report(
        report_id=report_id,
        current_user=user,
        export_format=format,
        case_id=case_id,
        http_request=request
    )
    safe_filename = filename.encode('ascii', 'ignore').decode('ascii').replace(' ', '_')
    if not safe_filename or safe_filename.startswith('.'):
        safe_filename = f"report_{report_id}.{format or 'json'}"

    headers = {
        "Content-Disposition": f'attachment; filename="{safe_filename}"'
    }
    return FastAPIResponse(content=artifact_bytes, media_type=media_type, headers=headers)
