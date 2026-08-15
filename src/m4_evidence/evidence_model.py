from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

@dataclass(frozen=True)
class M4EvidenceReference:
    """M4 domain object representing a single preserved evidence reference."""
    evidence_id: str
    evidence_type: str
    source_id: Optional[str] = None
    hash: Optional[str] = None
    hash_algorithm: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to contract-compliant dictionary representation."""
        data = {
            "evidence_id": self.evidence_id,
            "evidence_type": self.evidence_type,
            "source_id": self.source_id,
            "hash": self.hash,
            "hash_algorithm": self.hash_algorithm
        }
        return data

@dataclass
class M4EvidenceLinkage:
    """Tracks where an evidence ID is linked across the investigation case."""
    timeline_event_ids: List[str] = field(default_factory=list)
    relationship_ids: List[str] = field(default_factory=list)
    finding_ids: List[str] = field(default_factory=list)
    assessment_fact_statements: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "timeline_event_ids": sorted(list(set(self.timeline_event_ids))),
            "relationship_ids": sorted(list(set(self.relationship_ids))),
            "finding_ids": sorted(list(set(self.finding_ids))),
            "assessment_fact_statements": sorted(list(set(self.assessment_fact_statements)))
        }

@dataclass
class M4CaseEvidencePackage:
    """
    Immutable M4-owned evidence package holding extracted evidence references
    and linkages with full traceability back to the upstream InvestigationCase.
    """
    case_id: str
    schema_version: str
    created_at: str
    updated_at: str
    evidence_references: List[M4EvidenceReference] = field(default_factory=list)
    linkages: Dict[str, M4EvidenceLinkage] = field(default_factory=dict)

    def get_evidence(self, evidence_id: str) -> Optional[M4EvidenceReference]:
        """Lookup evidence reference by evidence_id."""
        for ref in self.evidence_references:
            if ref.evidence_id == evidence_id:
                return ref
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the complete package to dictionary format."""
        return {
            "schema_version": "evidence-reference-v1",
            "case_id": self.case_id,
            "upstream_schema_version": self.schema_version,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "evidence_references": [ref.to_dict() for ref in self.evidence_references],
            "linkages": {
                ev_id: link.to_dict() for ev_id, link in self.linkages.items()
            }
        }
