from enum import Enum
from typing import List, Optional
from datetime import datetime
from pydantic import BaseModel, Field

class MappingStatus(str, Enum):
    SUPPORTED = "SUPPORTED"
    PARTIAL = "PARTIAL"
    POTENTIAL = "POTENTIAL"
    INSUFFICIENT_EVIDENCE = "INSUFFICIENT_EVIDENCE"
    NOT_APPLICABLE = "NOT_APPLICABLE"

class MitreMapping(BaseModel):
    mapping_id: str
    finding_id: str
    behavior_id: str
    
    technique_id: str
    technique_name: str
    tactic_id: Optional[str] = None
    tactic_name: Optional[str] = None
    
    detection_strategy_ids: List[str] = Field(default_factory=list)
    analytic_ids: List[str] = Field(default_factory=list)
    data_component_ids: List[str] = Field(default_factory=list)
    channels: List[str] = Field(default_factory=list)
    
    mapping_status: MappingStatus
    mapping_confidence: float = Field(ge=0.0, le=1.0)
    rationale: str
    
    evidence_ids: List[str] = Field(default_factory=list, min_length=1)
    
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    
    knowledge_profile_id: str
    mitre_version: str
