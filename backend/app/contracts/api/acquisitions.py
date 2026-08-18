from typing import Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel
from .common import PaginatedResponse

class AcquisitionResponse(BaseModel):
    acquisition_id: UUID
    file_name: str
    file_size: Optional[int] = None
    sha256: str
    format: str
    source_type: str
    status: str
    ingested_at: datetime
    
    class Config:
        from_attributes = True

class AcquisitionUploadResponse(BaseModel):
    acquisition_id: UUID
    evidence_id: UUID
    case_id: UUID
    file_name: str
    format: str
    size_bytes: Optional[int] = None
    sha256: str
    status: str
    created_at: datetime

AcquisitionListResponse = PaginatedResponse[AcquisitionResponse]
