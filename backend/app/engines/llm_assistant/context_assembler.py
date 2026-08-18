import json
from typing import Dict, Any

from app.contracts.llm import (
    LLMInvestigationContext,
    LLMEvidence,
    LLMEvidenceData,
    LLMMitreMapping,
    LLMAttackChain,
    LLMAttackChainStage
)

class ContextAssemblerError(Exception):
    pass

class ContextAssembler:
    """
    Transforms an InvestigationCase V1.2 + raw evidence mapping into a deterministic,
    read-only LLMInvestigationContext suitable for Ollama/Qwen.
    """
    def __init__(self):
        pass

    def assemble(self, case_dict: Dict[str, Any], evidence_map: Dict[str, Any]) -> LLMInvestigationContext:
        if case_dict.get("schema_version") != "investigation-case-v1.2":
            raise ContextAssemblerError("LLM Context V1 supports InvestigationCase V1.2 only.")
        
        evidence_context = []
        # Structural distinction to prevent prompt injection
        for ev_id, ev_data in evidence_map.items():
            ev_type = ev_data.get("evidence_type", "unknown")
            ev_source = ev_data.get("source_id")
            ev_rel = ev_data.get("relationship")
            
            # Preserve status natively if present (e.g. OBSERVED, INFERRED, POTENTIAL)
            # We explicitly do not invent one if not present.
            ev_status = ev_data.get("status")
            
            # Serialize content purely as data
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
                tactic_id=m.get("tactic_id"),
                tactic_name=m.get("tactic_name"),
                behavior_id=m.get("behavior_id"),
                mapping_status=m.get("mapping_status", "UNKNOWN"),
                mapping_confidence=float(m.get("mapping_confidence", 0.0)),
                rationale=m.get("rationale"),
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
                status=ac.get("status", "none"),  # Preserve exact M3 status
                stages=stages
            )
            
        return LLMInvestigationContext(
            case_id=case_dict.get("case_id", ""),
            findings=case_dict.get("findings", []),
            entities=case_dict.get("entities", []),
            timeline=case_dict.get("timeline", []),
            relationships=case_dict.get("relationships", []),
            evidence_references=case_dict.get("evidence_references", []),
            mitre_mappings=mitre_mappings,
            mitre_provenance=case_dict.get("mitre_provenance"),
            attack_chain=llm_ac,
            evidence_context=evidence_context,
            source_metadata={"assembled_for": "llm"}
        )
