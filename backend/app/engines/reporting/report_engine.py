from copy import deepcopy
from datetime import datetime, timezone
from typing import Dict, Any, List, Union
from app.shared.contract_validation import ContractValidator

class ReportEngine:
    """
    M4 Report Engine foundation.
    Assembles InvestigationCase V1.1 and EvidenceIntegrity V1 packages into contract-compliant Report V1 objects.
    Projects M3 domain components into strict Report V1 view representations.
    Does NOT perform correlation, threat intelligence lookup, or AI inference.
    """

    def __init__(self, validator: ContractValidator):
        self.validator = validator

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
        evidence_integrity_records: Union[List[Dict[str, Any]], Any]
    ) -> Dict[str, Any]:
        """
        Generates a contract-compliant Report V1 dictionary from InvestigationCase and EvidenceIntegrity input.

        :param investigation_case: Dict representing InvestigationCase V1.1 payload.
        :param evidence_integrity_records: List of EvidenceIntegrity V1 dicts or an M4EvidencePackage instance.
        :return: Dict adhering strictly to docs/contracts/report-v1.json
        """
        if not isinstance(investigation_case, dict):
            raise ValueError("InvestigationCase input must be a dictionary.")

        # 1. Input immutability
        case_data = deepcopy(investigation_case)

        # Validate upstream InvestigationCase V1.1 schema
        self.validator.validate("investigation-case-v1.1.json", case_data)

        case_id = case_data["case_id"]

        # 2. Extract and validate evidence_integrity records
        if hasattr(evidence_integrity_records, "get_all_evidence_records"):
            raw_records = evidence_integrity_records.get_all_evidence_records()
        elif isinstance(evidence_integrity_records, list):
            raw_records = evidence_integrity_records
        else:
            raise ValueError("Evidence integrity records must be a list or M4EvidencePackage instance.")

        records_data = deepcopy(raw_records)

        # 3. Deduplicate evidence integrity records by unique evidence_id
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

        # 4. Derived summary evidence counters over UNIQUE evidence IDs
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

        # 5. Deterministic report_id and generated_at timestamp
        report_id = f"RPT-{case_id}"
        generated_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

        # 6. Project components into contract-compliant Report V1 definitions
        projected_findings = [self._project_finding(f) for f in case_data.get("findings", [])]
        projected_timeline = [self._project_timeline_event(te) for te in case_data.get("timeline", [])]
        projected_entities = [self._project_entity(e) for e in case_data.get("entities", [])]
        projected_relationships = [self._project_relationship(r) for r in case_data.get("relationships", [])]

        # 7. Assemble Report V1 payload
        report_payload: Dict[str, Any] = {
            "schema_version": "report-v1",
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
            report_payload["assessment"] = case_data["assessment"]
        if case_data.get("provenance") is not None:
            report_payload["provenance"] = case_data["provenance"]

        # 8. Validate generated report payload against frozen report-v1.json schema
        self.validator.validate("report-v1.json", report_payload)

        return report_payload
