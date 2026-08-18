from fastapi import APIRouter, Depends, Request, status, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from typing import Optional, List
from uuid import UUID

from app.auth.dependencies import verify_case_access, get_current_user, RequireRole, get_db
from app.persistence.models.identity_models import UserModel
from app.contracts.api.analysis import (
    StartAnalysisRequest,
    AnalysisStartResponse,
    AnalysisStatusResponse,
    AnalysisListResponse
)
from app.services.analysis_orchestrator import AnalysisOrchestratorService, get_analysis_orchestrator
from app.exceptions import ValidationError

router = APIRouter(tags=["Analysis"])

async def inject_analysis_orchestrator(db: AsyncSession = Depends(get_db)) -> AnalysisOrchestratorService:
    return get_analysis_orchestrator(db)

@router.post("/cases/{case_id}/analysis", response_model=AnalysisStartResponse, status_code=status.HTTP_202_ACCEPTED)
async def start_analysis(
    request: StartAnalysisRequest,
    background_tasks: BackgroundTasks,
    case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(RequireRole(["administrator", "investigator"])),
    orchestrator: AnalysisOrchestratorService = Depends(inject_analysis_orchestrator)
):
    """
    Start a new forensic analysis job for an acquisition.
    Executes asynchronously in the background. Note: BackgroundTasks are NOT crash-durable.
    """
    try:
        analysis_id = await orchestrator.start_analysis(
            case_id=case_id,
            acquisition_id=request.acquisition_id,
            user_id=current_user.user_id
        )
    except ValidationError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to start analysis job")

    # Queue the background execution
    background_tasks.add_task(
        orchestrator.execute_analysis_background,
        analysis_id=analysis_id,
        user_id=current_user.user_id
    )

    return AnalysisStartResponse(
        analysis_id=analysis_id,
        case_id=case_id,
        acquisition_id=request.acquisition_id,
        status="queued"
    )

@router.get("/cases/{case_id}/analysis", response_model=AnalysisListResponse)
async def list_case_analysis_jobs(
    case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    orchestrator: AnalysisOrchestratorService = Depends(inject_analysis_orchestrator)
):
    """
    Retrieve all analysis jobs linked to this case.
    """
    async with orchestrator.uow:
        jobs = await orchestrator.analysis_repo.get_jobs_by_case(case_id)
    
    responses = []
    for job in jobs:
        responses.append(AnalysisStatusResponse(
            analysis_id=job.analysis_id,
            case_id=job.case_id,
            acquisition_id=job.acquisition_id,
            status=job.status,
            current_stage=job.current_stage,
            started_at=job.started_at,
            completed_at=job.completed_at,
            progress=job.progress,
            result_available=job.status == "completed",
            error_code=job.error_code,
            error_message=job.error_message
        ))
        
    return AnalysisListResponse(jobs=responses)

@router.get("/cases/{case_id}/analysis/{analysis_id}", response_model=AnalysisStatusResponse)
async def get_analysis_status(
    analysis_id: UUID,
    case_id: UUID = Depends(verify_case_access),
    current_user: UserModel = Depends(get_current_user),
    orchestrator: AnalysisOrchestratorService = Depends(inject_analysis_orchestrator)
):
    """
    Retrieve the status of a specific analysis job.
    """
    job_dict = await orchestrator.get_job_status(analysis_id)
    if not job_dict:
        raise HTTPException(status_code=404, detail="Analysis job not found")
        
    if job_dict["case_id"] != case_id:
        raise HTTPException(status_code=403, detail="Analysis job does not belong to this case")

    return AnalysisStatusResponse(**job_dict)
