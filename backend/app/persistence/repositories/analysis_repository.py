from typing import Optional, List
import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, desc

from app.persistence.models.investigation_models import AnalysisJobModel

class AnalysisRepository:
    """Repository for managing AnalysisJob lifecycle."""

    def __init__(self, session: Session):
        self.session = session

    async def create_job(
        self,
        case_id: uuid.UUID,
        acquisition_id: uuid.UUID,
        created_by: Optional[uuid.UUID] = None
    ) -> AnalysisJobModel:
        job = AnalysisJobModel(
            case_id=case_id,
            acquisition_id=acquisition_id,
            status="queued",
            created_by=created_by,
        )
        self.session.add(job)
        return job

    async def get_job(self, analysis_id: uuid.UUID) -> Optional[AnalysisJobModel]:
        stmt = select(AnalysisJobModel).where(AnalysisJobModel.analysis_id == analysis_id)
        result = await self.session.execute(stmt)
        return result.scalars().first()

    async def get_jobs_by_case(self, case_id: uuid.UUID) -> List[AnalysisJobModel]:
        stmt = select(AnalysisJobModel).where(AnalysisJobModel.case_id == case_id).order_by(desc(AnalysisJobModel.created_at))
        result = await self.session.execute(stmt)
        return list(result.scalars().all())

    async def update_status(
        self,
        analysis_id: uuid.UUID,
        status: str,
        stage: Optional[str] = None,
        progress: Optional[int] = None,
        error_code: Optional[str] = None,
        error_message: Optional[str] = None
    ) -> Optional[AnalysisJobModel]:
        job = await self.get_job(analysis_id)
        if not job:
            return None
        
        job.status = status
        
        if stage is not None:
            job.current_stage = stage
        if progress is not None:
            job.progress = progress
        if error_code is not None:
            job.error_code = error_code
        if error_message is not None:
            job.error_message = error_message
            
        if status == "running" and job.started_at is None:
            job.started_at = datetime.now(timezone.utc)
        elif status in ["completed", "failed"]:
            job.completed_at = datetime.now(timezone.utc)

        return job

    async def has_active_analysis(self, acquisition_id: uuid.UUID) -> bool:
        """Check if an acquisition is currently queued or running."""
        stmt = select(AnalysisJobModel).where(
            and_(
                AnalysisJobModel.acquisition_id == acquisition_id,
                AnalysisJobModel.status.in_(["queued", "running"])
            )
        )
        result = await self.session.execute(stmt)
        return result.scalars().first() is not None
