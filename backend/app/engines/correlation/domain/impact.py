from dataclasses import dataclass, field
from typing import List
from enum import Enum

class ImpactStatus(Enum):
    OBSERVED = "OBSERVED"
    INFERRED = "INFERRED"
    POTENTIAL = "POTENTIAL"

@dataclass(frozen=True)
class ImpactAssessment:
    impact_id: str
    category: str
    statement: str
    status: ImpactStatus
    confidence: float
    supporting_evidence_ids: List[str]
    supporting_finding_ids: List[str] = field(default_factory=list)
    affected_entity_ids: List[str] = field(default_factory=list)
    rationale: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
