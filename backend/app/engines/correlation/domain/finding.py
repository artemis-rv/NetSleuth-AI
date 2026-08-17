from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass(frozen=True)
class FindingReference:
    finding_id: str
    finding_type: str
    severity: str
    confidence_score: float
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    entity_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)

    def __post_init__(self):
        if not self.finding_id:
            raise ValueError("Finding ID cannot be empty.")
        if not (0.0 <= self.confidence_score <= 1.0):
            raise ValueError("Confidence score must be between 0.0 and 1.0.")
