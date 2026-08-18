from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict, Any, List, Union, Optional
from app.shared.contract_validation import ContractValidator

class ReportEngine:
    """
    M4 Report Engine foundation.
    Assembles InvestigationCase (V1.1 or V1.2) and EvidenceIntegrity V1 packages into contract-compliant Report V1 objects.
    Projects M3 domain components into strict Report V1 view representations.
    Does NOT perform correlation, threat intelligence lookup, or AI inference.
    """

    def __init__(self, validator: ContractValidator):
        self.validator = validator

    def _detect_case_version(self, case_data: Dict[str, Any]) -> tuple[str, str, str]:
        schema_version = case_data.get("schema_version")
        if schema_version == "investigation-case-v1.1":
            return "investigation-case-v1.1.json", "report-v1", "report-v1.json"
        elif schema_version == "investigation-case-v1.2":
            return "investigation-case-v1.2.json", "report-v1.1", "report-v1.1.json"
        else:
            raise ValueError(f"Unsupported or unknown InvestigationCase schema_version '{schema_version}'.")

    def _project_finding(self, f: Dict[str, Any]) -> Dict[str, Any]:
        pf: Dict[str, Any] = {
            "finding_id": f["finding_id"],
            "title": f.get("title") or f["finding_id"],
            "severity": f.get("severity") or "informational",
            "confidence": float(f.get("confidence") if f.get("confidence") is not None else 1.0)
        }
        if f.get("finding_type") is not None:
            pf["finding_type"] = f["finding_type"]
        if f.get("description") is not None:
            pf["description"] = f["description"]
        if "evidence_references" in f and f["evidence_references"] is not None:
            pf["evidence_references"] = f["evidence_references"]
        return pf

    def _project_timeline_event(self, te: Dict[str, Any]) -> Dict[str, Any]:
        pte: Dict[str, Any] = {
            "event_id": te["event_id"],
            "timestamp": te["timestamp"],
            "title": te.get("title") or te["event_id"]
        }
        if te.get("description") is not None:
            pte["description"] = te["description"]
        if te.get("event_type") is not None:
            pte["event_type"] = te["event_type"]
        if "entity_ids" in te and te["entity_ids"] is not None:
            pte["entity_ids"] = te["entity_ids"]
        if "evidence_ids" in te and te["evidence_ids"] is not None:
            pte["evidence_ids"] = te["evidence_ids"]
        return pte

    def _project_entity(self, e: Dict[str, Any]) -> Dict[str, Any]:
        pe: Dict[str, Any] = {
            "entity_id": e["entity_id"],
            "entity_type": e["entity_type"],
            "value": e.get("value") or e["entity_id"]
        }
        if e.get("namespace") is not None:
            pe["namespace"] = e["namespace"]
        if e.get("confidence") is not None:
            pe["confidence"] = e["confidence"]
        return pe

    def _project_relationship(self, r: Dict[str, Any]) -> Dict[str, Any]:
        pr: Dict[str, Any] = {
            "relationship_id": r["relationship_id"],
            "source_entity_id": r["source_entity_id"],
            "target_entity_id": r["target_entity_id"],
            "relationship_type": r["relationship_type"]
        }
        if "evidence_ids" in r and r["evidence_ids"] is not None:
            pr["evidence_ids"] = r["evidence_ids"]
        return pr

    def generate_report(
        self,
        investigation_case: Dict[str, Any],
        evidence_integrity_records: Union[List[Dict[str, Any]], Any],
        llm_enrichment: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Generates a contract-compliant Report V1 dictionary from InvestigationCase and EvidenceIntegrity input.

        :param investigation_case: Dict representing InvestigationCase payload (V1.1 or V1.2).
        :param evidence_integrity_records: List of EvidenceIntegrity V1 dicts or an M4EvidencePackage instance.
        :return: Dict adhering strictly to docs/contracts/report-v1.json
        """
        if not isinstance(investigation_case, dict):
            raise ValueError("InvestigationCase input must be a dictionary.")

        # 1. Input immutability
        case_data = deepcopy(investigation_case)

        # 2. Schema version detection
        schema_version = case_data.get("schema_version")
        if schema_version == "investigation-case-v1.1":
            case_schema_file = "investigation-case-v1.1.json"
            out_schema_version = "report-v1"
            out_schema_file = "report-v1.json"
        elif schema_version == "investigation-case-v1.2":
            case_schema_file = "investigation-case-v1.2.json"
            if llm_enrichment is not None:
                out_schema_version = "report-v1.2"
                out_schema_file = "report-v1.2.json"
            else:
                out_schema_version = "report-v1.1"
                out_schema_file = "report-v1.1.json"
        elif schema_version == "investigation-case-v1.3":
            case_schema_file = "investigation-case-v1.3.json"
            out_schema_version = "report-v1.3"
            out_schema_file = "report-v1.3.json"
        else:
            raise ValueError(f"Unsupported or unknown InvestigationCase schema_version '{schema_version}'.")

        # Validate upstream InvestigationCase schema
        self.validator.validate(case_schema_file, case_data)

        case_id = case_data["case_id"]

        # 3. Extract and validate evidence_integrity records
        if hasattr(evidence_integrity_records, "get_all_evidence_records"):
            raw_records = evidence_integrity_records.get_all_evidence_records()
        elif isinstance(evidence_integrity_records, list):
            raw_records = evidence_integrity_records
        else:
            raise ValueError("Evidence integrity records must be a list or M4EvidencePackage instance.")

        records_data = deepcopy(raw_records)

        # 4. Deduplicate evidence integrity records by unique evidence_id
        unique_records_map: Dict[str, Dict[str, Any]] = {}
        for rec in records_data:
            if not isinstance(rec, dict):
                raise ValueError("Evidence integrity record must be a dictionary.")
            self.validator.validate("evidence-integrity-v1.json", rec)

            ev_id = rec["evidence_id"]
            if ev_id in unique_records_map:
                prev = unique_records_map[ev_id]
                # Compare immutable metadata for conflict detection
                if (
                    prev.get("evidence_type") != rec.get("evidence_type") or
                    prev.get("source_id") != rec.get("source_id")
                ):
                    raise ValueError(f"Conflicting duplicate evidence metadata for ID '{ev_id}'.")
            unique_records_map[ev_id] = rec

        unique_records = list(unique_records_map.values())

        # 5. Derived summary evidence counters over UNIQUE evidence IDs
        verified_count = 0
        mismatched_count = 0
        unverified_count = 0

        for rec in unique_records:
            status = rec.get("verification_status", "unverified")
            if status == "verified":
                verified_count += 1
            elif status in ("mismatch", "tampered"):
                mismatched_count += 1
            else:
                unverified_count += 1

        total_unique_references = len(unique_records)

        # Invariant check
        if verified_count + mismatched_count + unverified_count != total_unique_references:
            raise ValueError("Summary evidence counter invariant violation.")

        # 6. Deterministic report_id and generated_at timestamp
        report_id = f"RPT-{case_id}"
        generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # 7. Project components into contract-compliant Report definitions
        projected_findings = [self._project_finding(f) for f in case_data.get("findings", [])]
        projected_timeline = [self._project_timeline_event(te) for te in case_data.get("timeline", [])]
        projected_entities = [self._project_entity(e) for e in case_data.get("entities", [])]
        projected_relationships = [self._project_relationship(r) for r in case_data.get("relationships", [])]

        # 8. Assemble Report payload
        report_payload: Dict[str, Any] = {
            "schema_version": out_schema_version,
            "report_id": report_id,
            "case_id": case_id,
            "generated_at": generated_at,
            "generator_version": "NetSleuth-AI M4 v1.0",
            "summary": {
                "case_title": case_data["title"],
                "case_description": case_data.get("description"),
                "case_status": case_data["status"],
                "total_findings": len(projected_findings),
                "total_timeline_events": len(projected_timeline),
                "total_evidence_references": total_unique_references,
                "verified_evidence_count": verified_count,
                "mismatched_evidence_count": mismatched_count,
                "unverified_evidence_count": unverified_count
            },
            "findings": projected_findings,
            "timeline": projected_timeline,
            "entities": projected_entities,
            "relationships": projected_relationships,
            "evidence_integrity": unique_records
        }

        if case_data.get("assessment") is not None:
            if schema_version == "investigation-case-v1.3":
                # For V1.3, we preserve facts if present, and explicitly project new arrays
                assm = {"summary": "Investigation Engine Results"}
                if "facts" in case_data["assessment"]:
                    assm["facts"] = case_data["assessment"]["facts"]
                if "hypotheses" in case_data["assessment"]:
                    assm["hypotheses"] = [self._project_hypothesis(h) for h in case_data["assessment"]["hypotheses"]]
                if "hypothesis_validations" in case_data["assessment"]:
                    assm["hypothesis_validations"] = [self._project_hypothesis_validation(hv) for hv in case_data["assessment"]["hypothesis_validations"]]
                if "root_causes" in case_data["assessment"]:
                    assm["root_causes"] = [self._project_root_cause(rc) for rc in case_data["assessment"]["root_causes"]]
                if "impact_assessments" in case_data["assessment"]:
                    assm["impact_assessments"] = [self._project_impact_assessment(ia) for ia in case_data["assessment"]["impact_assessments"]]
                report_payload["assessment"] = assm
            else:
                report_payload["assessment"] = self._project_assessment(case_data["assessment"])
        if case_data.get("provenance") is not None:
            report_payload["provenance"] = case_data["provenance"]

        # 9. Project V1.1 MITRE intelligence for V1.2 and V1.3 cases
        if schema_version in ("investigation-case-v1.2", "investigation-case-v1.3"):
            if "mitre_mappings" in case_data and case_data["mitre_mappings"] is not None:
                report_payload["mitre_mappings"] = [self._project_mitre_mapping(m) for m in case_data["mitre_mappings"]]
            if "mitre_provenance" in case_data and case_data["mitre_provenance"] is not None:
                report_payload["mitre_provenance"] = self._project_mitre_provenance(case_data["mitre_provenance"])
            if "attack_chain" in case_data and case_data["attack_chain"] is not None:
                report_payload["attack_chain"] = self._project_attack_chain(case_data["attack_chain"])
            
            # 9.5 Add LLM Enrichment
            if llm_enrichment is not None:
                report_payload["llm_enrichment"] = deepcopy(llm_enrichment)

        # 10. Validate generated report payload against corresponding schema contract
        self.validator.validate(out_schema_file, report_payload)

        return report_payload

    def _project_mitre_mapping(self, m: Dict[str, Any]) -> Dict[str, Any]:
        pm: Dict[str, Any] = {
            "technique_id": m["technique_id"],
            "technique_name": m["technique_name"]
        }
        for k in (
            "tactic_id", "tactic_name", "behavior_id", "mapping_status",
            "mapping_confidence", "rationale", "source_finding_ids", "evidence_ids",
            "first_seen", "last_seen", "detection_strategy_ids", "analytic_ids",
            "data_component_ids", "channels"
        ):
            if k in m:
                pm[k] = m[k]
        return pm

    def _project_mitre_provenance(self, p: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "framework": p["framework"],
            "domain": p["domain"],
            "version": p["version"],
            "knowledge_profile_id": p["knowledge_profile_id"]
        }

    def _project_attack_chain(self, ac: Dict[str, Any]) -> Dict[str, Any]:
        pac: Dict[str, Any] = {
            "status": ac.get("status", "none")
        }
        if "stages" in ac and ac["stages"] is not None:
            projected_stages = []
            for st in ac["stages"]:
                pst: Dict[str, Any] = {
                    "stage_id": st["stage_id"],
                    "name": st["name"]
                }
                for k in ("timestamp", "event_ids", "finding_ids"):
                    if k in st:
                        pst[k] = st[k]
                projected_stages.append(pst)
            pac["stages"] = projected_stages
        return pac

    def _project_assessment(self, ass: Dict[str, Any]) -> Dict[str, Any]:
        summary_text = ass.get("summary")
        if not summary_text:
            facts = ass.get("facts") or []
            if facts and isinstance(facts, list) and len(facts) > 0 and isinstance(facts[0], dict):
                summary_text = facts[0].get("statement") or "Investigation Assessment Summary."
            else:
                summary_text = "Investigation Assessment Summary."

        pass_ass: Dict[str, Any] = {
            "summary": summary_text
        }

        if "facts" in ass and ass["facts"] is not None:
            projected_facts = []
            for idx, fact in enumerate(ass["facts"]):
                if isinstance(fact, dict):
                    pf: Dict[str, Any] = {
                        "fact_id": fact.get("fact_id") or f"FACT-{idx+1}",
                        "statement": fact["statement"]
                    }
                    if fact.get("confidence") is not None:
                        pf["confidence"] = fact["confidence"]
                    if "source_ids" in fact and fact["source_ids"] is not None:
                        pf["source_ids"] = fact["source_ids"]
                    projected_facts.append(pf)
            pass_ass["facts"] = projected_facts

        return pass_ass

    def _project_hypothesis(self, h: Dict[str, Any]) -> Dict[str, Any]:
        ph: Dict[str, Any] = {
            "hypothesis_id": h["hypothesis_id"],
            "statement": h["statement"],
            "hypothesis_type": h["hypothesis_type"],
            "status": h["status"],
            "confidence": h["confidence"],
            "supporting_evidence_ids": list(h["supporting_evidence_ids"])
        }
        for k in (
            "supporting_finding_ids", "related_entity_ids", "related_mitre_mapping_ids",
            "first_seen", "last_seen", "supporting_reasons", "missing_evidence"
        ):
            if k in h:
                ph[k] = h[k]
        return ph

    def _project_hypothesis_validation(self, hv: Dict[str, Any]) -> Dict[str, Any]:
        phv: Dict[str, Any] = {
            "validation_id": hv["validation_id"],
            "hypothesis_id": hv["hypothesis_id"],
            "validation_status": hv["validation_status"],
            "confidence": hv["confidence"],
            "validated_at": hv["validated_at"]
        }
        for k in (
            "supporting_evidence_ids", "contradicting_evidence_ids", 
            "supporting_reasons", "contradicting_reasons", "missing_evidence"
        ):
            if k in hv:
                phv[k] = hv[k]
        return phv

    def _project_root_cause(self, rc: Dict[str, Any]) -> Dict[str, Any]:
        prc: Dict[str, Any] = {
            "root_cause_id": rc["root_cause_id"],
            "statement": rc["statement"],
            "status": rc["status"],
            "confidence": rc["confidence"],
            "supporting_evidence_ids": list(rc["supporting_evidence_ids"])
        }
        for k in (
            "supporting_hypothesis_ids", "supporting_finding_ids",
            "rationale", "missing_evidence"
        ):
            if k in rc:
                prc[k] = rc[k]
        return prc

    def _project_impact_assessment(self, ia: Dict[str, Any]) -> Dict[str, Any]:
        pia: Dict[str, Any] = {
            "impact_id": ia["impact_id"],
            "category": ia["category"],
            "statement": ia["statement"],
            "status": ia["status"],
            "confidence": ia["confidence"],
            "supporting_evidence_ids": list(ia["supporting_evidence_ids"])
        }
        for k in (
            "supporting_finding_ids", "affected_entity_ids",
            "rationale", "missing_evidence"
        ):
            if k in ia:
                pia[k] = ia[k]
        return pia
