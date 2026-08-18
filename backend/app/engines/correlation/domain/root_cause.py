from dataclasses import dataclass, field
from typing import List
from enum import Enum

class RootCauseStatus(Enum):
    POTENTIAL = "POTENTIAL"
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    UNRESOLVED = "UNRESOLVED"

@dataclass(frozen=True)
class RootCause:
    root_cause_id: str
    statement: str
    status: RootCauseStatus
    confidence: float
    supporting_evidence_ids: List[str]
    supporting_hypothesis_ids: List[str] = field(default_factory=list)
    supporting_finding_ids: List[str] = field(default_factory=list)
    rationale: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
