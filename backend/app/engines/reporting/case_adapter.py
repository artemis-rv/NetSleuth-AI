from typing import Dict, Any, List
from app.shared.contract_validation import ContractValidator
from app.engines.reporting.evidence_model import (
    M4EvidenceReference,
    M4EvidenceLinkage,
    M4CaseEvidencePackage
)

class M3ToM4EvidenceAdapter:
    """
    Forensic adapter that ingests a frozen M3 InvestigationCase V1.1 JSON payload,
    validates contract compliance, and extracts/preserves all evidence references
    and linkages without altering, inventing, or inferring evidence.
    """

    def __init__(self, validator: ContractValidator):
        self.validator = validator

    def adapt(self, investigation_case_payload: Dict[str, Any]) -> M4CaseEvidencePackage:
        """
        Adapts an InvestigationCase V1.1 object into an M4-owned evidence package.

        :param investigation_case_payload: Dict containing InvestigationCase V1.1 data.
        :return: M4CaseEvidencePackage with exact preserved evidence references and linkages.
        """
        # 1. Contract Validation
        self.validator.validate("investigation-case-v1.1.json", investigation_case_payload)

        # 2. Extract Case Metadata
        case_id = investigation_case_payload["case_id"]
        schema_version = investigation_case_payload["schema_version"]
        created_at = investigation_case_payload["created_at"]
        updated_at = investigation_case_payload["updated_at"]

        # 3. Extract Evidence References
        raw_evidence_refs = investigation_case_payload.get("evidence_references", [])
        evidence_references: List[M4EvidenceReference] = []
        seen_evidence_ids = set()
        linkages: Dict[str, M4EvidenceLinkage] = {}

        for raw_ref in raw_evidence_refs:
            ev_id = raw_ref["evidence_id"]
            ev_type = raw_ref["evidence_type"]

            # Initialize linkage container for every explicit evidence reference
            if ev_id not in linkages:
                linkages[ev_id] = M4EvidenceLinkage()

            # Handle duplicate evidence references deterministically
            if ev_id in seen_evidence_ids:
                continue

            seen_evidence_ids.add(ev_id)

            ref = M4EvidenceReference(
                evidence_id=ev_id,
                evidence_type=ev_type,
                source_id=raw_ref.get("source_id"),
                hash=raw_ref.get("hash"),
                hash_algorithm=raw_ref.get("hash_algorithm")
            )
            evidence_references.append(ref)

        # 4. Extract Evidence Linkages across Timeline Events
        for event in investigation_case_payload.get("timeline", []):
            event_id = event.get("event_id")
            for ev_id in event.get("evidence_ids", []):
                if ev_id not in linkages:
                    linkages[ev_id] = M4EvidenceLinkage()
                if event_id:
                    linkages[ev_id].timeline_event_ids.append(event_id)

        # 5. Extract Evidence Linkages across Relationships
        for rel in investigation_case_payload.get("relationships", []):
            rel_id = rel.get("relationship_id")
            for ev_id in rel.get("evidence_ids", []):
                if ev_id not in linkages:
                    linkages[ev_id] = M4EvidenceLinkage()
                if rel_id:
                    linkages[ev_id].relationship_ids.append(rel_id)

        # 6. Extract Evidence Linkages from Findings
        for finding_ref in investigation_case_payload.get("findings", []):
            finding_id = finding_ref.get("finding_id")
            # If findings reference evidence, preserve linkage if specified
            if finding_id and "evidence_ids" in finding_ref:
                for ev_id in finding_ref.get("evidence_ids", []):
                    if ev_id not in linkages:
                        linkages[ev_id] = M4EvidenceLinkage()
                    linkages[ev_id].finding_ids.append(finding_id)

        # 7. Extract Evidence Linkages from Assessment Facts
        assessment = investigation_case_payload.get("assessment")
        if assessment and isinstance(assessment, dict):
            for fact in assessment.get("facts", []):
                statement = fact.get("statement", "")
                for ev_id in fact.get("source_ids", []):
                    if ev_id not in linkages:
                        linkages[ev_id] = M4EvidenceLinkage()
                    if statement:
                        linkages[ev_id].assessment_fact_statements.append(statement)

        return M4CaseEvidencePackage(
            case_id=case_id,
            schema_version=schema_version,
            created_at=created_at,
            updated_at=updated_at,
            evidence_references=evidence_references,
            linkages=linkages
        )
