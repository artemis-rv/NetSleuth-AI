from copy import deepcopy
from typing import Dict, Any, List, Optional
from src.shared.contract_validation import ContractValidator
from src.m4_evidence.evidence_model import M4CaseEvidencePackage, M4EvidenceReference
from src.m4_evidence.case_adapter import M3ToM4EvidenceAdapter
from src.m4_evidence.integrity_verifier import IntegrityVerifier
from src.m4_evidence.chain_of_custody import ChainOfCustody

class M4EvidencePackage:
    """
    Orchestrated M4 Evidence Package holding evidence references, verification results,
    and chain of custody logs with full contract compliance and traceability to upstream InvestigationCase.
    """

    def __init__(
        self,
        case_id: str,
        case_evidence_package: M4CaseEvidencePackage,
        validator: ContractValidator,
        raw_case_payload: Dict[str, Any]
    ):
        self.case_id = case_id
        self.case_evidence_package = case_evidence_package
        self.validator = validator
        self.raw_case_payload = raw_case_payload
        self.verifier = IntegrityVerifier(validator)
        self.custody_logs: Dict[str, ChainOfCustody] = {}
        self.verification_results: Dict[str, Dict[str, Any]] = {}

    def get_evidence_reference(self, evidence_id: str) -> M4EvidenceReference:
        ref = self.case_evidence_package.get_evidence(evidence_id)
        if not ref:
            raise ValueError(f"Evidence ID '{evidence_id}' is not declared in case '{self.case_id}'.")
        return ref

    def verify_evidence(
        self,
        evidence_id: str,
        evidence_bytes: bytes,
        custodian_id: str = "m4-integrity-verifier"
    ) -> Dict[str, Any]:
        """
        Calculates hash of evidence bytes, compares against expected hash, records 'verify' custody action,
        and updates verification status.
        """
        ref = self.get_evidence_reference(evidence_id)

        metadata = {
            "evidence_id": ref.evidence_id,
            "case_id": self.case_id,
            "evidence_type": ref.evidence_type,
            "source_id": ref.source_id,
            "expected_hash": ref.hash,
            "hash_algorithm": ref.hash_algorithm
        }

        # Execute verifier
        result = self.verifier.verify(metadata, evidence_bytes)
        self.verification_results[evidence_id] = result

        # Record verify custody action ONLY if verification actually executed
        if evidence_id not in self.custody_logs:
            self.custody_logs[evidence_id] = ChainOfCustody(evidence_id)
        self.custody_logs[evidence_id].record_action(
            custodian_id=custodian_id,
            action="verify",
            timestamp=result.get("verified_at")
        )

        return self.get_evidence_record(evidence_id)

    def export_evidence(
        self,
        evidence_id: str,
        custodian_id: str = "m4-exporter"
    ) -> Dict[str, Any]:
        """Records an 'export' custody action for specified evidence."""
        self.get_evidence_reference(evidence_id)
        if evidence_id not in self.custody_logs:
            self.custody_logs[evidence_id] = ChainOfCustody(evidence_id)
        self.custody_logs[evidence_id].record_action(
            custodian_id=custodian_id,
            action="export"
        )
        return self.get_evidence_record(evidence_id)

    def get_evidence_record(self, evidence_id: str) -> Dict[str, Any]:
        """
        Assembles and schema-validates a single Evidence Integrity V1 dictionary.
        """
        ref = self.get_evidence_reference(evidence_id)

        # Existing verification result if computed, else default unverified structure
        ver_result = self.verification_results.get(evidence_id)
        if ver_result:
            calc_hash = ver_result.get("calculated_hash")
            ver_status = ver_result.get("verification_status", "unverified")
            ver_at = ver_result.get("verified_at")
        else:
            calc_hash = None
            ver_status = "unverified"
            ver_at = None

        custody_entries = []
        if evidence_id in self.custody_logs:
            custody_entries = self.custody_logs[evidence_id].get_entries()

        record: Dict[str, Any] = {
            "schema_version": "evidence-integrity-v1",
            "evidence_id": ref.evidence_id,
            "case_id": self.case_id,
            "evidence_type": ref.evidence_type,
            "verification_status": ver_status,
        }

        if ref.source_id is not None:
            record["source_id"] = ref.source_id
        if ref.hash is not None:
            record["expected_hash"] = ref.hash
        if calc_hash is not None:
            record["calculated_hash"] = calc_hash
        if ref.hash_algorithm is not None:
            record["hash_algorithm"] = ref.hash_algorithm
        if ver_at is not None:
            record["verified_at"] = ver_at
        if custody_entries:
            record["chain_of_custody"] = custody_entries

        # Schema validation
        self.validator.validate("evidence-integrity-v1.json", record)

        return record

    def get_all_evidence_records(self) -> List[Dict[str, Any]]:
        """Returns all evidence records in the package."""
        return [
            self.get_evidence_record(ref.evidence_id)
            for ref in self.case_evidence_package.evidence_references
        ]


class M4EvidencePackageBuilder:
    """
    Builder that orchestrates M3ToM4EvidenceAdapter, IntegrityVerifier, and ChainOfCustody
    to assemble contract-compliant M4EvidencePackage objects.
    """

    def __init__(self, validator: ContractValidator):
        self.validator = validator
        self.adapter = M3ToM4EvidenceAdapter(validator)

    def build(
        self,
        investigation_case_payload: Dict[str, Any],
        evidence_payloads: Optional[Dict[str, bytes]] = None,
        custodian_id: str = "m4-ingest-engine"
    ) -> M4EvidencePackage:
        """
        Orchestrates package construction from InvestigationCase V1.1 payload.

        :param investigation_case_payload: Raw InvestigationCase V1.1 dictionary.
        :param evidence_payloads: Optional dict mapping evidence_id -> raw evidence bytes.
        :param custodian_id: Identifier of ingesting custodian.
        :return: Orchestrated M4EvidencePackage instance.
        """
        # 1. Do not mutate original input payload
        case_payload = deepcopy(investigation_case_payload)

        # 2. Check referential integrity across timeline, relationships, findings, assessment
        declared_ev_ids = {
            ev["evidence_id"] for ev in case_payload.get("evidence_references", [])
        }

        for event in case_payload.get("timeline", []):
            for ev_id in event.get("evidence_ids", []):
                if ev_id not in declared_ev_ids:
                    raise ValueError(
                        f"Timeline event '{event.get('event_id')}' references undeclared evidence ID '{ev_id}'."
                    )

        for rel in case_payload.get("relationships", []):
            for ev_id in rel.get("evidence_ids", []):
                if ev_id not in declared_ev_ids:
                    raise ValueError(
                        f"Relationship '{rel.get('relationship_id')}' references undeclared evidence ID '{ev_id}'."
                    )

        for fact in case_payload.get("assessment", {}).get("facts", []):
            for ev_id in fact.get("source_ids", []):
                if ev_id not in declared_ev_ids:
                    raise ValueError(
                        f"Assessment fact references undeclared evidence ID '{ev_id}'."
                    )

        # 3. Check for conflicting duplicate evidence metadata
        seen_refs: Dict[str, Dict[str, Any]] = {}
        for ref in case_payload.get("evidence_references", []):
            ev_id = ref["evidence_id"]
            if ev_id in seen_refs:
                prev = seen_refs[ev_id]
                # Compare key immutable attributes
                if (
                    prev.get("evidence_type") != ref.get("evidence_type") or
                    prev.get("source_id") != ref.get("source_id") or
                    prev.get("hash") != ref.get("hash") or
                    prev.get("hash_algorithm") != ref.get("hash_algorithm")
                ):
                    raise ValueError(
                        f"Duplicate evidence ID '{ev_id}' has conflicting metadata: {prev} vs {ref}."
                    )
            else:
                seen_refs[ev_id] = ref

        # 4. Adapt case using M3ToM4Adapter
        adapted_pkg = self.adapter.adapt(case_payload)
        case_id = case_payload["case_id"]

        # 5. Instantiate package orchestrator
        pkg = M4EvidencePackage(
            case_id=case_id,
            case_evidence_package=adapted_pkg,
            validator=self.validator,
            raw_case_payload=case_payload
        )

        # 6. Record ingest custody action for each evidence reference
        for ref in adapted_pkg.evidence_references:
            ev_id = ref.evidence_id
            coc = ChainOfCustody(ev_id, self.validator)
            coc.record_action(custodian_id=custodian_id, action="ingest")
            pkg.custody_logs[ev_id] = coc

        # 7. Execute verification if evidence bytes supplied
        if evidence_payloads:
            for ev_id, ev_bytes in evidence_payloads.items():
                if ev_id in declared_ev_ids:
                    pkg.verify_evidence(ev_id, ev_bytes, custodian_id=custodian_id)

        # 8. Schema validate all evidence records
        for ref in adapted_pkg.evidence_references:
            pkg.get_evidence_record(ref.evidence_id)

        return pkg
