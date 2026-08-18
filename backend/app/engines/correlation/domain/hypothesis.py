from dataclasses import dataclass, field
from typing import List, Optional
from datetime import datetime
from enum import Enum

class HypothesisStatus(Enum):
    POTENTIAL = "POTENTIAL"
    SUPPORTED = "SUPPORTED"
    PARTIALLY_SUPPORTED = "PARTIALLY_SUPPORTED"
    DISFAVORED = "DISFAVORED"
    REJECTED = "REJECTED"
    UNRESOLVED = "UNRESOLVED"

class ValidationStatus(Enum):
    VALIDATED = "VALIDATED"
    REJECTED = "REJECTED"
    INCONCLUSIVE = "INCONCLUSIVE"

@dataclass(frozen=True)
class Hypothesis:
    hypothesis_id: str
    statement: str
    hypothesis_type: str
    status: HypothesisStatus
    confidence: float
    supporting_evidence_ids: List[str]
    supporting_finding_ids: List[str] = field(default_factory=list)
    related_entity_ids: List[str] = field(default_factory=list)
    related_mitre_mapping_ids: List[str] = field(default_factory=list)
    supporting_reasons: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None

@dataclass(frozen=True)
class HypothesisValidation:
    validation_id: str
    hypothesis_id: str
    validation_status: ValidationStatus
    confidence: float
    validated_at: datetime
    supporting_evidence_ids: List[str] = field(default_factory=list)
    contradicting_evidence_ids: List[str] = field(default_factory=list)
    supporting_reasons: List[str] = field(default_factory=list)
    contradicting_reasons: List[str] = field(default_factory=list)
    missing_evidence: List[str] = field(default_factory=list)
