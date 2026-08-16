import unittest
import json
import hashlib
from pathlib import Path
from src.shared.contract_validation import ContractValidator
from src.m4_evidence.evidence_package import M4EvidencePackageBuilder

class TestM4Integration(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.builder = M4EvidencePackageBuilder(self.validator)

        fixture_path = (
            Path(__file__).resolve().parent.parent.parent
            / "fixtures"
            / "investigations"
            / "investigation-case-v1-scenario-001-expected.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.scenario_001_case = json.load(f)

    def test_scenario_001_end_to_end_m4_evidence_pipeline(self):
        """
        End-to-end integration test:
        Loads Scenario 001 InvestigationCase V1.1 -> Adapts -> Verifies bytes via IntegrityVerifier ->
        Records ChainOfCustody -> Validates full Evidence Integrity V1 output.
        """
        # 1. Deterministic evidence payloads for test evidence references
        ev_references = self.scenario_001_case["evidence_references"]
        self.assertGreater(len(ev_references), 0)

        sample_pcap_bytes = b"ZEEK-PCAP-STREAM-SCENARIO-001-PAYLOAD"
        calculated_pcap_hash = hashlib.sha256(sample_pcap_bytes).hexdigest()

        # Update test case expected hash for first reference
        ev_id = ev_references[0]["evidence_id"]
        ev_references[0]["hash"] = calculated_pcap_hash
        ev_references[0]["hash_algorithm"] = "SHA-256"

        evidence_payloads = {
            ev_id: sample_pcap_bytes
        }

        # 2. Build M4 Package
        pkg = self.builder.build(
            investigation_case_payload=self.scenario_001_case,
            evidence_payloads=evidence_payloads,
            custodian_id="m4-integration-test-custodian"
        )

        # 3. Export evidence
        pkg.export_evidence(ev_id, custodian_id="m4-export-custodian")

        # 4. Verify evidence record
        verified_record = pkg.get_evidence_record(ev_id)

        self.assertEqual(verified_record["schema_version"], "evidence-integrity-v1")
        self.assertEqual(verified_record["evidence_id"], ev_id)
        self.assertEqual(verified_record["case_id"], self.scenario_001_case["case_id"])
        self.assertEqual(verified_record["verification_status"], "verified")
        self.assertEqual(verified_record["expected_hash"], calculated_pcap_hash)
        self.assertEqual(verified_record["calculated_hash"], calculated_pcap_hash)
        self.assertEqual(verified_record["hash_algorithm"], "SHA-256")
        self.assertIsNotNone(verified_record["verified_at"])

        # Check chain of custody entries
        custody_actions = [c["action"] for c in verified_record["chain_of_custody"]]
        self.assertEqual(custody_actions, ["ingest", "verify", "export"])

        # 5. Validate all evidence records in final package against contract schema
        all_records = pkg.get_all_evidence_records()
        self.assertGreaterEqual(len(all_records), len(ev_references))
        for record in all_records:
            self.validator.validate("evidence-integrity-v1.json", record)
