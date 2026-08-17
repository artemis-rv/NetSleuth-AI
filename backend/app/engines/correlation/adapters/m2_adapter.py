from datetime import datetime, timezone
from typing import Dict, Any

from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.entity import Entity
from app.engines.correlation.domain.finding import FindingReference
from app.engines.correlation.domain.relationship import Relationship
from app.engines.correlation.domain.evidence import EvidenceReference
from app.shared.contract_validation import ContractValidator

class M2Adapter:
    def __init__(self, validator: ContractValidator):
        self.validator = validator

    def _parse_timestamp(self, ts_str: str) -> datetime:
        if not ts_str:
            return None
        try:
            dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
                raise ValueError("Timestamp must be timezone-aware.")
            return dt.astimezone(timezone.utc)
        except Exception as e:
            raise ValueError(f"Invalid timestamp format: {ts_str}") from e

    def adapt(self, m2_payload: Dict[str, Any], ctx: InvestigationContext = None) -> InvestigationContext:
        self.validator.validate("finding-v1.json", m2_payload)
        
        if ctx is None:
            ctx = InvestigationContext()
            
        # Preserve acquisition_id
        if not ctx.acquisition_id:
            ctx.acquisition_id = m2_payload.get("acquisition_id")

        first_seen = self._parse_timestamp(m2_payload.get("first_seen", ""))
        last_seen = self._parse_timestamp(m2_payload.get("last_seen", ""))
        
        finding_id = m2_payload["finding_id"]
        
        finding_ent_ids = []
        finding_ev_ids = []

        # 1. Map Evidence References
        for ev in m2_payload.get("evidence_references", []):
            ref_type = ev["reference_type"]
            ref_id = ev["reference_id"]
            
            # Safe generic mapping for ambiguous protocols
            ev_type = ref_type
            if ref_type == "protocol_event":
                ev_type = "log" # Safe generic fallback, do not guess protocol
                
            evidence_id = f"ev-{ref_id}"
            finding_ev_ids.append(evidence_id)
            
            # Add to context if it doesn't already exist to avoid duplicate generic entries
            if not any(e.evidence_id == evidence_id for e in ctx.evidence_references):
                ctx.evidence_references.append(EvidenceReference(
                    evidence_id=evidence_id,
                    evidence_type=ev_type,
                    source_id=ref_id
                ))

        # We need a way to find the role for a given entity_id if it exists in evidence_references
        role_map = {}
        for ev in m2_payload.get("evidence_references", []):
            role_map[f"{ev['reference_type']}:{ev['reference_id']}"] = ev.get("role", "supporting")
            if ev["reference_type"] == "protocol_event":
                role_map[f"protocol_event:{ev['reference_id']}"] = ev.get("role", "supporting")

        # 2. Map Entities and Explicit Relationships
        for ent_ref in m2_payload.get("entities", []):
            ent_type = ent_ref["entity_type"]
            ent_id = ent_ref["entity_id"]
            ns_entity_id = f"{ent_type}:{ent_id}"
            
            finding_ent_ids.append(ns_entity_id)
            
            # Shell entity reference ensures existence in context
            # InvestigationContext.add_entity() will safely merge or append.
            shell_ent = Entity(
                entity_id=ns_entity_id,
                entity_type=ent_type,
                value=ent_id,
                attributes={"original_m2_id": ent_id}
            )
            ctx.add_entity(shell_ent)
            
            role = role_map.get(ns_entity_id)
            
            # Create explicit finding -> entity relationship
            rel = Relationship(
                relationship_id=f"rel-{finding_id}-{ns_entity_id}",
                source_entity_id=f"finding:{finding_id}",
                relationship_type="explicit_reference",
                target_entity_id=ns_entity_id,
                confidence=1.0,
                evidence_ids=finding_ev_ids,
                attributes={"role": role} if role else {}
            )
            ctx.relationships.append(rel)
            
        # 3. Map FindingReference
        f_ref = FindingReference(
            finding_id=finding_id,
            finding_type=m2_payload["finding_type"],
            severity=m2_payload["severity"],
            confidence_score=float(m2_payload.get("confidence_score", 1.0)),
            first_seen=first_seen,
            last_seen=last_seen,
            entity_ids=finding_ent_ids,
            evidence_ids=finding_ev_ids
        )
        ctx.findings.append(f_ref)
        
        # 4. Expose the finding itself as a formal Entity to anchor relationships
        # IMPORTANT: For the hackathon, this exists purely as a temporary graph relationship anchor.
        # The canonical source of truth for findings remains the FindingReference objects
        # added to ctx.findings above. Do not rely on this Entity for finding data!
        finding_entity = Entity(
            entity_id=f"finding:{finding_id}",
            entity_type="finding",
            value=finding_id,
            first_seen=first_seen,
            last_seen=last_seen,
            attributes={"provenance": m2_payload.get("provenance", {})}
        )
        ctx.add_entity(finding_entity)

        return ctx
