from typing import Dict, Any
from datetime import datetime, timezone

from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.hypothesis import ValidationStatus
from app.shared.contract_validation import ContractValidator

class InvestigationCaseBuilder:
    def __init__(self, validator: ContractValidator):
        self.validator = validator
        
    def _build_attack_chain(self, ctx: InvestigationContext) -> Dict[str, Any]:
        qualifying_mappings = []
        if hasattr(ctx, "mitre_mappings") and ctx.mitre_mappings:
            for m in ctx.mitre_mappings:
                status_str = m.mapping_status.value if hasattr(m.mapping_status, "value") else str(m.mapping_status)
                if status_str in ("SUPPORTED", "PARTIAL", "POTENTIAL"):
                    qualifying_mappings.append(m)

        if not qualifying_mappings:
            return {"status": "none"}
            
        # Reserved for future explicit deterministic chain-confirmation rule.
        # Until then, any qualifying stage makes the chain 'potential' at most.
        status = "potential"
        
        # Sort mappings deterministically: first_seen, last_seen, technique_id
        def sort_key(m):
            t1 = m.first_seen.isoformat() if getattr(m, "first_seen", None) else "9999-99-99T99:99:99Z"
            t2 = m.last_seen.isoformat() if getattr(m, "last_seen", None) else "9999-99-99T99:99:99Z"
            return (t1, t2, m.technique_id)
            
        qualifying_mappings.sort(key=sort_key)
        
        stages = []
        for m in qualifying_mappings:
            stage_doc = {
                "stage_id": f"stage-{m.technique_id}",
                "name": m.technique_name
            }
            if getattr(m, "first_seen", None):
                stage_doc["timestamp"] = m.first_seen.isoformat().replace("+00:00", "Z")
            if getattr(m, "finding_id", None):
                stage_doc["finding_ids"] = [m.finding_id]
                
            # Cross-reference timeline events that have matching evidence IDs
            if getattr(m, "evidence_ids", None):
                stage_event_ids = []
                for t in getattr(ctx, "timeline_events", []):
                    if getattr(t, "evidence_ids", None):
                        if set(m.evidence_ids).intersection(set(t.evidence_ids)):
                            stage_event_ids.append(t.event_id)
                if stage_event_ids:
                    # Deduplicate while preserving order
                    seen = set()
                    unique_event_ids = []
                    for eid in stage_event_ids:
                        if eid not in seen:
                            seen.add(eid)
                            unique_event_ids.append(eid)
                    stage_doc["event_ids"] = unique_event_ids
                    
            stages.append(stage_doc)
            
        return {
            "status": status,
            "stages": stages
        }

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
        


        has_v1_3_fields = any([
            getattr(ctx, 'hypotheses', []),
            getattr(ctx, 'hypothesis_validations', []),
            getattr(ctx, 'root_causes', []),
            getattr(ctx, 'impact_assessments', [])
        ])
        
        schema_version = "investigation-case-v1.3" if has_v1_3_fields else "investigation-case-v1.2"

        doc = {
            "schema_version": schema_version,
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
            "attack_chain": self._build_attack_chain(ctx),
            "mitre_provenance": {
                "framework": "MITRE ATT&CK",
                "domain": "enterprise",
                "version": "19.2",
                "knowledge_profile_id": "netsleuth-network-evidence-v1"
            },
            "mitre_mappings": []
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
                "entity_type": e.entity_type if e.entity_type in valid_types else "artifact"
            }
            if hasattr(e, "attributes") and e.attributes:
                e_doc["attributes"] = e.attributes
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
                    
        # 7. Assessment (V1.3 extensions)
        if has_v1_3_fields:
            assessment_doc = {
                "hypotheses": [],
                "hypothesis_validations": [],
                "root_causes": [],
                "impact_assessments": []
            }
            
            for h in ctx.hypotheses:
                h_doc = {
                    "hypothesis_id": h.hypothesis_id,
                    "statement": h.statement,
                    "hypothesis_type": h.hypothesis_type,
                    "status": h.status.value,
                    "confidence": float(h.confidence),
                    "supporting_evidence_ids": list(h.supporting_evidence_ids)
                }
                if h.supporting_finding_ids: h_doc["supporting_finding_ids"] = list(h.supporting_finding_ids)
                if h.related_entity_ids: h_doc["related_entity_ids"] = list(h.related_entity_ids)
                if h.related_mitre_mapping_ids: h_doc["related_mitre_mapping_ids"] = list(h.related_mitre_mapping_ids)
                if h.supporting_reasons: h_doc["supporting_reasons"] = list(h.supporting_reasons)
                if h.missing_evidence: h_doc["missing_evidence"] = list(h.missing_evidence)
                if h.first_seen: h_doc["first_seen"] = h.first_seen.isoformat().replace("+00:00", "Z")
                if h.last_seen: h_doc["last_seen"] = h.last_seen.isoformat().replace("+00:00", "Z")
                
                # Check evidence integrity
                for ev_id in h.supporting_evidence_ids:
                    if ev_id not in declared_ev_ids:
                        raise ValueError(f"Hypothesis '{h.hypothesis_id}' references undeclared evidence ID '{ev_id}'.")
                
                assessment_doc["hypotheses"].append(h_doc)
                
            for v in ctx.hypothesis_validations:
                v_doc = {
                    "validation_id": v.validation_id,
                    "hypothesis_id": v.hypothesis_id,
                    "validation_status": v.validation_status.value,
                    "confidence": float(v.confidence),
                    "validated_at": v.validated_at.isoformat().replace("+00:00", "Z")
                }
                if v.supporting_evidence_ids: v_doc["supporting_evidence_ids"] = list(v.supporting_evidence_ids)
                if v.contradicting_evidence_ids: v_doc["contradicting_evidence_ids"] = list(v.contradicting_evidence_ids)
                if v.supporting_reasons: v_doc["supporting_reasons"] = list(v.supporting_reasons)
                if v.contradicting_reasons: v_doc["contradicting_reasons"] = list(v.contradicting_reasons)
                if v.missing_evidence: v_doc["missing_evidence"] = list(v.missing_evidence)
                
                if v.validation_status in (ValidationStatus.VALIDATED, ValidationStatus.REJECTED):
                    if not v.supporting_evidence_ids and not v.contradicting_evidence_ids:
                        raise ValueError("Validation must have evidence when VALIDATED or REJECTED.")
                
                # Check evidence integrity
                for ev_id in list(v.supporting_evidence_ids) + list(v.contradicting_evidence_ids):
                    if ev_id not in declared_ev_ids:
                        raise ValueError(f"Validation '{v.validation_id}' references undeclared evidence ID '{ev_id}'.")
                        
                assessment_doc["hypothesis_validations"].append(v_doc)
                
            for rc in ctx.root_causes:
                rc_doc = {
                    "root_cause_id": rc.root_cause_id,
                    "statement": rc.statement,
                    "status": rc.status.value,
                    "confidence": float(rc.confidence),
                    "supporting_evidence_ids": list(rc.supporting_evidence_ids)
                }
                if rc.supporting_hypothesis_ids: rc_doc["supporting_hypothesis_ids"] = list(rc.supporting_hypothesis_ids)
                if rc.supporting_finding_ids: rc_doc["supporting_finding_ids"] = list(rc.supporting_finding_ids)
                if rc.rationale: rc_doc["rationale"] = list(rc.rationale)
                if rc.missing_evidence: rc_doc["missing_evidence"] = list(rc.missing_evidence)
                
                # Check evidence integrity
                for ev_id in rc.supporting_evidence_ids:
                    if ev_id not in declared_ev_ids:
                        raise ValueError(f"RootCause '{rc.root_cause_id}' references undeclared evidence ID '{ev_id}'.")
                        
                assessment_doc["root_causes"].append(rc_doc)
                
            for imp in ctx.impact_assessments:
                imp_doc = {
                    "impact_id": imp.impact_id,
                    "category": imp.category,
                    "statement": imp.statement,
                    "status": imp.status.value,
                    "confidence": float(imp.confidence),
                    "supporting_evidence_ids": list(imp.supporting_evidence_ids)
                }
                if imp.supporting_finding_ids: imp_doc["supporting_finding_ids"] = list(imp.supporting_finding_ids)
                if imp.affected_entity_ids: imp_doc["affected_entity_ids"] = list(imp.affected_entity_ids)
                if imp.rationale: imp_doc["rationale"] = list(imp.rationale)
                if imp.missing_evidence: imp_doc["missing_evidence"] = list(imp.missing_evidence)
                
                # Check evidence integrity
                for ev_id in imp.supporting_evidence_ids:
                    if ev_id not in declared_ev_ids:
                        raise ValueError(f"ImpactAssessment '{imp.impact_id}' references undeclared evidence ID '{ev_id}'.")
                        
                assessment_doc["impact_assessments"].append(imp_doc)
                
            doc["assessment"] = assessment_doc

        # 8. MITRE Mappings
        if hasattr(ctx, "mitre_mappings") and ctx.mitre_mappings:
            for m in ctx.mitre_mappings:
                m_doc = {
                    "technique_id": m.technique_id,
                    "technique_name": m.technique_name
                }
                if m.tactic_id:
                    m_doc["tactic_id"] = m.tactic_id
                if m.tactic_name:
                    m_doc["tactic_name"] = m.tactic_name
                if m.behavior_id:
                    m_doc["behavior_id"] = m.behavior_id
                if m.mapping_status:
                    # Enum conversion to string
                    m_doc["mapping_status"] = m.mapping_status.value if hasattr(m.mapping_status, "value") else str(m.mapping_status)
                if m.mapping_confidence is not None:
                    m_doc["mapping_confidence"] = float(m.mapping_confidence)
                if m.rationale:
                    m_doc["rationale"] = m.rationale
                if m.finding_id:
                    m_doc["source_finding_ids"] = [m.finding_id]
                
                # Check for evidence_ids which is technically defined as a list in MitreMapping
                if getattr(m, "evidence_ids", None):
                    m_doc["evidence_ids"] = list(m.evidence_ids)
                    
                if getattr(m, "first_seen", None):
                    m_doc["first_seen"] = m.first_seen.isoformat().replace("+00:00", "Z")
                if getattr(m, "last_seen", None):
                    m_doc["last_seen"] = m.last_seen.isoformat().replace("+00:00", "Z")
                    
                if getattr(m, "detection_strategy_ids", None):
                    m_doc["detection_strategy_ids"] = list(m.detection_strategy_ids)
                if getattr(m, "analytic_ids", None):
                    m_doc["analytic_ids"] = list(m.analytic_ids)
                if getattr(m, "data_component_ids", None):
                    m_doc["data_component_ids"] = list(m.data_component_ids)
                if getattr(m, "channels", None):
                    m_doc["channels"] = list(m.channels)
                    
                doc["mitre_mappings"].append(m_doc)

        # Validate output against schema
        self.validator.validate(f"{schema_version}.json", doc)
        
        return doc
