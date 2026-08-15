from dataclasses import dataclass
from typing import Optional

CANONICAL_EVIDENCE_TYPES = {
    "pcap", "flow", "session", "dns", "http", "tls", "artifact", "log", "finding"
}

@dataclass(frozen=True)
class EvidenceReference:
    evidence_id: str
    evidence_type: str
    source_id: Optional[str] = None

    def __post_init__(self):
        if not self.evidence_id:
            raise ValueError("Evidence ID cannot be empty.")
        if self.evidence_type not in CANONICAL_EVIDENCE_TYPES:
            raise ValueError(f"Evidence type '{self.evidence_type}' is not one of the canonical V1 types.")
