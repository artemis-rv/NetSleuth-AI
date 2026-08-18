import uuid
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime

class StartAnalysisRequest(BaseModel):
    acquisition_id: uuid.UUID = Field(..., description="ID of the acquisition to analyze")

class AnalysisStartResponse(BaseModel):
    analysis_id: uuid.UUID
    case_id: uuid.UUID
    acquisition_id: uuid.UUID
    status: str = Field(description="Initial status, usually 'queued'")

class AnalysisStatusResponse(BaseModel):
    analysis_id: uuid.UUID
    case_id: uuid.UUID
    acquisition_id: uuid.UUID
    status: str
    current_stage: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    progress: Optional[int] = None
    result_available: bool = False
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime

class AnalysisListResponse(BaseModel):
    jobs: List[AnalysisStatusResponse]

