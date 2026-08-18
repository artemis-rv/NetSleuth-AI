from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Any, Dict
from uuid import UUID
from datetime import datetime

class EvidenceItemBase(BaseModel):
    case_id: UUID
    evidence_id: Optional[UUID] = None
    label: str
    description: Optional[str] = None
    evidence_type: str
    sha256: Optional[str] = None

class EvidenceItemResponse(EvidenceItemBase):
    evidence_item_id: UUID
    minio_bucket: Optional[str] = None
    object_key: Optional[str] = None
    registered_at: datetime
    registered_by: Optional[UUID] = None
    model_config = ConfigDict(from_attributes=True)

class EvidenceItemListResponse(BaseModel):
    items: List[EvidenceItemResponse]
    total: int
    page: int
    page_size: int

class CustodyEventBase(BaseModel):
    action: str
    notes: Optional[str] = None
    event_metadata: Optional[Dict[str, Any]] = None

class CustodyEventResponse(CustodyEventBase):
    custody_event_id: UUID
    evidence_item_id: UUID
    actor_id: Optional[UUID] = None
    actor_name: Optional[str] = None
    occurred_at: datetime
    model_config = ConfigDict(from_attributes=True)

class CustodyEventListResponse(BaseModel):
    items: List[CustodyEventResponse]
    total: int
    page: int
    page_size: int
