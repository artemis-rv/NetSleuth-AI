from pydantic import BaseModel, ConfigDict
from typing import List, Optional
from uuid import UUID
from datetime import datetime

class ReportBase(BaseModel):
    case_id: UUID
    report_type: str
    title: Optional[str] = None
    format: str

class ReportResponse(ReportBase):
    report_id: UUID
    version: int
    minio_bucket: str
    object_key: str
    sha256: str
    generated_at: datetime
    generated_by: Optional[UUID] = None
    model_config = ConfigDict(from_attributes=True)

class ReportListResponse(BaseModel):
    items: List[ReportResponse]
    total: int
    page: int
    page_size: int
