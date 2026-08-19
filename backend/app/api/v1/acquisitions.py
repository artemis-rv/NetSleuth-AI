from fastapi import APIRouter, Depends, Request, status, Query, UploadFile, File
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional
from uuid import UUID

from app.auth.dependencies import verify_case_access, get_current_user, RequireRole, get_db
from app.persistence.models.identity_models import UserModel
from app.contracts.api.acquisitions import AcquisitionUploadResponse, AcquisitionResponse, AcquisitionListResponse
from app.services.app_acquisition_service import AppAcquisitionService

router = APIRouter(tags=["Acquisitions"])

from typing import Optional, List, Union

@router.post("/cases/{case_id}/acquisitions", status_code=status.HTTP_201_CREATED)
async def upload_acquisition(
    http_request: Request,
    case_id: UUID = Depends(verify_case_access),
    files: Optional[List[UploadFile]] = File(None),
    file: Optional[UploadFile] = File(None),
    current_user: UserModel = Depends(RequireRole(["administrator", "investigator"])),
    db: AsyncSession = Depends(get_db)
):
    """
    Upload PCAP/PCAPNG evidence for an investigation case.
    Validates file, computes SHA-256, stores in MinIO, and creates metadata.
    Supports single or multiple file uploads.
    """
    upload_files = []
    if files:
        upload_files.extend(files)
    if file:
        upload_files.append(file)
    if not upload_files:
        from fastapi import HTTPException
        raise HTTPException(status_code=400, detail="No file provided")

    service = AppAcquisitionService(db)
    results = []
    for f in upload_files:
        res = await service.upload_evidence(case_id, current_user, f, http_request)
        results.append(res)
    
    if file and not files:
        return results[0]
    return results

@router.get("/cases/{case_id}/acquisitions", response_model=AcquisitionListResponse)
async def list_acquisitions(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    status: Optional[str] = Query(None),
    format: Optional[str] = Query(None),
    case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    List acquisitions for a specific case.
    """
    service = AppAcquisitionService(db)
    return await service.list_acquisitions(case_id, current_user, page, page_size, status, format)

@router.get("/acquisitions/{acquisition_id}", response_model=AcquisitionResponse)
async def get_acquisition(
    http_request: Request,
    acquisition_id: UUID,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieve single acquisition. 
    Authorization is enforced by resolving the case linkage within the service, 
    but since we rely on `verify_case_access` normally, let's explicitly verify here.
    """
    service = AppAcquisitionService(db)
    # Get acquisition first to find its case_id
    acq = await service.get_acquisition(acquisition_id, current_user)
    
    # Verify access to the case it belongs to
    from app.persistence.models.investigation_models import case_acquisition_links
    from sqlalchemy import select
    
    stmt = select(case_acquisition_links.c.case_id).where(case_acquisition_links.c.acquisition_id == acquisition_id)
    result = await db.execute(stmt)
    case_id = result.scalar_one_or_none()
    
    if case_id:
        from app.auth.dependencies import verify_case_access_direct
        await verify_case_access_direct(case_id, current_user, db, http_request)
        
    return acq
