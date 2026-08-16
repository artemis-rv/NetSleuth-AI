from typing import Dict, Any
from datetime import datetime, timezone

from src.m3_correlation.domain.investigation import InvestigationContext
from src.shared.contract_validation import ContractValidator

class InvestigationCaseBuilder:
    def __init__(self, validator: ContractValidator):
        self.validator = validator
        
    def build(self, ctx: InvestigationContext) -> Dict[str, Any]:
        case_id = getattr(ctx, 'case_id', None)
        if not case_id:
            # Deterministic fallback per requirements
            if getattr(ctx, 'acquisition_id', None):
                case_id = f"CASE-{ctx.acquisition_id}"
            else:
                raise ValueError("InvestigationContext has no case_id and no acquisition_id to fallback on.")
                
        # Calculate times deterministically
        timeline = ctx.timeline_events
        if timeline:
            created_at = timeline[0].timestamp.isoformat()
            updated_at = timeline[-1].timestamp.isoformat()
        else:
            raise ValueError("InvestigationContext has no timeline events to establish deterministic created_at.")
            
        # Determine Severity from Findings (default 'medium')
        severities = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_sev = 2
        for f in ctx.findings:
            if f.severity in severities:
                max_sev = max(max_sev, severities[f.severity])
        
        sev_map = {4: "critical", 3: "high", 2: "medium", 1: "low"}
        severity = sev_map[max_sev]
        
        # Build document
        doc = {
            "schema_version": "investigation-case-v1.1",
            "case_id": case_id,
            "title": f"Investigation Case {case_id}",
            "description": "Automatically assembled investigation case.",
            "status": "open",
            "severity": severity,
            "created_at": created_at.replace("+00:00", "Z"),
            "updated_at": updated_at.replace("+00:00", "Z"),
            "investigator": {
                "investigator_id": "m3-correlation-engine",
                "name": "NetSleuth M3 Engine"
            },
            "findings": [],
            "timeline": [],
            "entities": [],
            "relationships": [],
            "evidence_references": [],
            "attack_chain": {
                "status": "none"
            }
        }
        
        # 1. Findings
        for f in ctx.findings:
            doc["findings"].append({
                "finding_id": f.finding_id,
                "role": "primary"
            })
            
        # 2. Timeline
        for t in ctx.timeline_events:
            t_doc = {
                "event_id": t.event_id,
                "timestamp": t.timestamp.isoformat().replace("+00:00", "Z"),
                "event_type": t.event_type if t.event_type in ["network", "dns", "http", "tls", "session", "flow", "artifact", "finding", "alert", "investigation", "evidence"] else "network",
                "description": t.description
            }
            # Map all entity references without truncation.
            if t.entity_ids:
                t_doc["entity_ids"] = t.entity_ids
                t_doc["source_entity_id"] = t.entity_ids[0]
                if len(t.entity_ids) > 1:
                    t_doc["target_entity_id"] = t.entity_ids[1]
            if t.evidence_ids:
                t_doc["evidence_ids"] = t.evidence_ids
            doc["timeline"].append(t_doc)
            
        # 3. Entities
        valid_types = ["host", "ip", "domain", "url", "session", "flow", "protocol_event", "ioc", "artifact", "finding"]
        for e in ctx.entities:
            e_doc = {
                "entity_id": e.entity_id,
                # Protocol_event is now fully supported.
                "entity_type": e.entity_type if e.entity_type in valid_types else "artifact"
            }
            if e.first_seen:
                e_doc["first_seen"] = e.first_seen.isoformat().replace("+00:00", "Z")
            if e.last_seen:
                e_doc["last_seen"] = e.last_seen.isoformat().replace("+00:00", "Z")
            doc["entities"].append(e_doc)
            
        # 4. Evidence
        valid_ev_types = ["pcap", "flow", "session", "dns", "http", "tls", "artifact", "log", "finding"]
        for ev in ctx.evidence_references:
            doc["evidence_references"].append({
                "evidence_id": ev.evidence_id,
                "evidence_type": ev.evidence_type if ev.evidence_type in valid_ev_types else "log",
                "source_id": ev.source_id
            })
            
        # 5. Relationships
        for r in ctx.relationships:
            r_doc = {
                "relationship_id": r.relationship_id,
                "source_entity_id": r.source_entity_id,
                "relationship_type": r.relationship_type,
                "target_entity_id": r.target_entity_id,
                "confidence": r.confidence,
                "evidence_ids": r.evidence_ids
            }
            if r.reason:
                r_doc["reason"] = r.reason
            if r.first_seen:
                r_doc["first_seen"] = r.first_seen.isoformat().replace("+00:00", "Z")
            if r.last_seen:
                r_doc["last_seen"] = r.last_seen.isoformat().replace("+00:00", "Z")
            doc["relationships"].append(r_doc)
        
        # 6. Referential Integrity Check for Evidence References
        declared_ev_ids = {ev["evidence_id"] for ev in doc["evidence_references"]}
        for t_event in doc["timeline"]:
            for ev_id in t_event.get("evidence_ids", []):
                if ev_id not in declared_ev_ids:
                    raise ValueError(f"Timeline event '{t_event['event_id']}' references undeclared evidence ID '{ev_id}'.")

        for rel in doc["relationships"]:
            for ev_id in rel.get("evidence_ids", []):
                if ev_id not in declared_ev_ids:
                    raise ValueError(f"Relationship '{rel['relationship_id']}' references undeclared evidence ID '{ev_id}'.")

        # Validate output against schema
        self.validator.validate("investigation-case-v1.1.json", doc)
        
        return doc
