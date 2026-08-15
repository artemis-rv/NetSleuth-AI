from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional, Dict, Any

@dataclass(frozen=True)
class Relationship:
    relationship_id: str
    source_entity_id: str
    relationship_type: str
    target_entity_id: str
    confidence: float = 1.0
    evidence_ids: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    reason: Optional[str] = None
    attributes: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.relationship_id:
            raise ValueError("Relationship ID cannot be empty.")
        if not self.source_entity_id:
            raise ValueError("Source entity ID cannot be empty.")
        if not self.target_entity_id:
            raise ValueError("Target entity ID cannot be empty.")
        if not (0.0 <= self.confidence <= 1.0):
            raise ValueError("Confidence must be between 0.0 and 1.0.")
