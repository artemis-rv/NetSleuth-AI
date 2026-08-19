import json
from typing import Dict, Any, List

from app.contracts.llm import (
    LLMInvestigationContext,
    LLMEvidence,
    LLMEvidenceData,
    LLMMitreMapping,
    LLMAttackChain,
    LLMAttackChainStage,
    LLMHypothesis,
    LLMValidation,
    LLMRootCause,
    LLMImpact,
    LLMReportRef,
    LLMSystemKnowledge
)

class ContextAssemblerError(Exception):
    pass

class ContextAssembler:
    """
    Transforms an InvestigationCase (V1.2/V1.3) + raw evidence mapping into a deterministic,
    read-only LLMInvestigationContext suitable for Ollama/Qwen.
    """
    def __init__(self):
        pass

    def assemble(self, case_dict: Dict[str, Any], evidence_map: Dict[str, Any] = None) -> LLMInvestigationContext:
        evidence_map = evidence_map or {}
        version = case_dict.get("schema_version", "investigation-case-v1.3")
        if not version.startswith("investigation-case-v1."):
            raise ContextAssemblerError(f"Unsupported schema version: {version}")
        
        evidence_context = []
        # Structural distinction to prevent prompt injection
        for ev_id, ev_data in evidence_map.items():
            ev_type = ev_data.get("evidence_type", "unknown")
            ev_source = ev_data.get("source_id")
            ev_rel = ev_data.get("relationship")
            ev_status = ev_data.get("status")
            
            raw_data = ev_data.get("data", "")
            if isinstance(raw_data, str):
                text_repr = raw_data
            else:
                text_repr = json.dumps(raw_data)

            evidence_context.append(LLMEvidence(
                evidence_id=ev_id,
                evidence_type=ev_type,
                source_id=ev_source,
                relationship_to_case=ev_rel,
                status=ev_status,
                timestamp=ev_data.get("timestamp"),
                evidence_data=LLMEvidenceData(text=text_repr, content_type="evidence")
            ))
            
        mitre_mappings = []
        for m in case_dict.get("mitre_mappings", []):
            mitre_mappings.append(LLMMitreMapping(
                technique_id=m.get("technique_id", ""),
                technique_name=m.get("technique_name", ""),
                tactic_id=m.get("tactic_id") or m.get("tactic"),
                tactic_name=m.get("tactic_name") or m.get("tactic"),
                behavior_id=m.get("behavior_id"),
                mapping_status=m.get("mapping_status", "SUPPORTED"),
                mapping_confidence=float(m.get("mapping_confidence", 0.95)),
                rationale=m.get("rationale") or m.get("justification"),
                source_finding_ids=m.get("source_finding_ids", []),
                evidence_ids=m.get("evidence_ids", []),
                first_seen=m.get("first_seen"),
                last_seen=m.get("last_seen"),
                detection_strategy_ids=m.get("detection_strategy_ids", []),
                analytic_ids=m.get("analytic_ids", []),
                data_component_ids=m.get("data_component_ids", []),
                channels=m.get("channels", [])
            ))
            
        ac = case_dict.get("attack_chain")
        llm_ac = None
        if ac:
            stages = []
            for s in ac.get("stages", []):
                stages.append(LLMAttackChainStage(
                    stage_id=s.get("stage_id", ""),
                    name=s.get("name", ""),
                    timestamp=s.get("timestamp"),
                    event_ids=s.get("event_ids", []),
                    finding_ids=s.get("finding_ids", [])
                ))
            llm_ac = LLMAttackChain(
                status=ac.get("status", "potential"),
                stages=stages
            )

        hypotheses = []
        for h in case_dict.get("hypotheses", []):
            hypotheses.append(LLMHypothesis(
                hypothesis_id=str(h.get("hypothesis_id", "")),
                statement=h.get("statement", ""),
                hypothesis_type=h.get("hypothesis_type"),
                status=h.get("status", "unverified"),
                confidence=float(h.get("confidence", 0.5)),
                supporting_evidence=h.get("supporting_evidence", []),
                supporting_findings=h.get("supporting_findings", []),
                reasons=h.get("reasons", []),
                missing_evidence=h.get("missing_evidence", [])
            ))

        validations = []
        for v in case_dict.get("validations", []):
            validations.append(LLMValidation(
                validation_id=str(v.get("validation_id", "")),
                hypothesis_id=str(v.get("hypothesis_id", "")),
                status=v.get("status", "pending"),
                confidence=float(v.get("confidence", 0.5)),
                supporting_evidence=v.get("supporting_evidence", []),
                contradicting_evidence=v.get("contradicting_evidence", []),
                reasons=v.get("reasons", []),
                missing_evidence=v.get("missing_evidence", [])
            ))

        root_causes = []
        for rc in case_dict.get("root_causes", []):
            root_causes.append(LLMRootCause(
                root_cause_id=str(rc.get("root_cause_id", "")),
                statement=rc.get("statement", ""),
                status=rc.get("status", "POTENTIAL"),
                confidence=float(rc.get("confidence", 0.5)),
                supporting_hypotheses=rc.get("supporting_hypotheses", []),
                supporting_evidence=rc.get("supporting_evidence", []),
                rationale=rc.get("rationale"),
                missing_evidence=rc.get("missing_evidence", [])
            ))

        impacts = []
        for imp in case_dict.get("impacts", []):
            impacts.append(LLMImpact(
                impact_id=str(imp.get("impact_id", "")),
                category=imp.get("category", "SYSTEM"),
                statement=imp.get("statement", ""),
                status=imp.get("status", "POTENTIAL"),
                confidence=float(imp.get("confidence", 0.5)),
                evidence=imp.get("evidence", []),
                affected_entities=imp.get("affected_entities", []),
                rationale=imp.get("rationale"),
                missing_evidence=imp.get("missing_evidence", [])
            ))

        reports = []
        for r in case_dict.get("reports", []):
            reports.append(LLMReportRef(
                report_id=str(r.get("report_id", "")),
                report_version=r.get("report_version", "v1.3"),
                provenance=r.get("provenance", {})
            ))

        case_meta = case_dict.get("case_metadata", {
            "title": case_dict.get("title", ""),
            "status": case_dict.get("status", "OPEN"),
            "priority": case_dict.get("priority", "HIGH"),
        })
            
        return LLMInvestigationContext(
            case_id=str(case_dict.get("case_id", "")),
            case_metadata=case_meta,
            findings=case_dict.get("findings", []),
            entities=case_dict.get("entities", []),
            timeline=case_dict.get("timeline", []),
            relationships=case_dict.get("relationships", []),
            evidence_references=case_dict.get("evidence_references", []),
            mitre_mappings=mitre_mappings,
            mitre_provenance=case_dict.get("mitre_provenance"),
            attack_chain=llm_ac,
            evidence_context=evidence_context,
            hypotheses=hypotheses,
            validations=validations,
            root_causes=root_causes,
            impacts=impacts,
            reports=reports,
            system_knowledge=LLMSystemKnowledge(),
            source_metadata={"assembled_for": "llm", "version": "v1.3"}
        )
