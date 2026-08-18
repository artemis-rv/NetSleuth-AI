from pydantic import BaseModel, ConfigDict, Field
from typing import Optional, List, Dict, Any
from uuid import UUID
from datetime import datetime

class FindingListItem(BaseModel):
    finding_id: UUID
    activity: str
    decision_state: str
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    severity: str
    detection_method: str
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    detected_at: datetime

    model_config = ConfigDict(from_attributes=True)

class FindingDetailResponse(FindingListItem):
    package_id: UUID
    acquisition_id: UUID
    anomaly_score: Optional[float] = None
    anomaly_detected: bool
    risk_policy_version: Optional[str] = None
    classification_probabilities: Optional[Dict[str, Any]] = None
    feature_attribution: Optional[Dict[str, Any]] = None
    rationale: Optional[str] = None
    model_version: Optional[str] = None
    feature_schema_version: Optional[str] = None
    version: int
    supersedes_id: Optional[UUID] = None

class FindingListResponse(BaseModel):
    items: List[FindingListItem]
    total: int
    page: int
    page_size: int
