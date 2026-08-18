from typing import Optional
from uuid import UUID
from datetime import datetime
from pydantic import BaseModel
from .common import PaginatedResponse

class EvidenceResponse(BaseModel):
    evidence_id: UUID
    acquisition_id: UUID
    file_name: str
    size_bytes: Optional[int] = None
    sha256: str
    format: str
    status: str
    integrity_status: str
    registered_at: datetime
    
    class Config:
        from_attributes = True

class EvidenceVerificationResponse(BaseModel):
    evidence_id: UUID
    expected_sha256: str
    observed_sha256: Optional[str] = None
    integrity_status: str  # "verified", "mismatch", or "missing"

EvidenceListResponse = PaginatedResponse[EvidenceResponse]
