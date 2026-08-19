from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional

@dataclass(frozen=True)
class TimelineEvent:
    event_id: str
    timestamp: datetime
    event_type: str
    title: str = ""
    description: str = ""
    entity_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    evidence_ids: List[str] = field(default_factory=list)
    flow_ids: List[str] = field(default_factory=list)
    protocol_event_ids: List[str] = field(default_factory=list)
    artifact_ids: List[str] = field(default_factory=list)
    relationship_ids: List[str] = field(default_factory=list)
    mitre_mapping_ids: List[str] = field(default_factory=list)
    status: Optional[str] = None
    provenance: Optional[str] = None
    source_reference: Optional[str] = None

    def __post_init__(self):
        if not self.event_id:
            raise ValueError("Event ID cannot be empty.")
        if not isinstance(self.timestamp, datetime):
            raise ValueError("Timestamp must be a valid datetime object.")
        if self.timestamp.tzinfo is None or self.timestamp.tzinfo.utcoffset(self.timestamp) is None:
            raise ValueError("TimelineEvent timestamp must be timezone-aware.")
