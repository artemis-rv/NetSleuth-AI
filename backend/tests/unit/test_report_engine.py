import unittest
import json
from pathlib import Path
from copy import deepcopy

from app.shared.contract_validation import ContractValidator
from app.engines.reporting.report_engine import ReportEngine


class TestReportEngineVersionAware(unittest.TestCase):
    """
    Comprehensive tests for M4 ReportEngine version-aware output support (V1.1 case -> Report V1, V1.2 case -> Report V1.1).
    """

    def setUp(self):
        self.validator = ContractValidator()
        self.engine = ReportEngine(self.validator)

        fixtures_dir = Path(__file__).resolve().parent.parent.parent.parent / "fixtures"

        # Load InvestigationCase V1.1 fixture
        v1_1_case_path = fixtures_dir / "investigations" / "investigation-case-v1-valid.json"
        with open(v1_1_case_path, "r", encoding="utf-8") as f:
            self.v1_1_case = json.load(f)

        # Load InvestigationCase V1.2 fixture
        v1_2_case_path = fixtures_dir / "investigations" / "investigation-case-v1.2-valid.json"
        with open(v1_2_case_path, "r", encoding="utf-8") as f:
            self.v1_2_case = json.load(f)

        # Valid EvidenceIntegrity V1 record fixture
        self.valid_evidence_integrity = [
            {
                "schema_version": "evidence-integrity-v1",
                "evidence_id": "ev-001",
                "case_id": "CASE-12345",
                "evidence_type": "flow",
                "source_id": "flow-001",
                "expected_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "calculated_hash": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2",
                "hash_algorithm": "SHA-256",
                "verification_status": "verified",
                "verified_at": "2026-08-15T11:00:00Z",
                "collected_at": "2026-08-15T09:45:00Z",
                "ingested_at": "2026-08-15T09:50:00Z",
                "provenance": {
                    "collector_id": "zeek-01"
                },
                "chain_of_custody": [
                    {
                        "custodian_id": "system",
                        "action": "ingest",
                        "timestamp": "2026-08-15T09:50:00Z"
                    }
                ]
            }
        ]

    # 1. V1.1 case -> report-v1
    def test_1_v1_1_case_produces_report_v1(self):
        report = self.engine.generate_report(self.v1_1_case, self.valid_evidence_integrity)
        self.assertEqual(report["schema_version"], "report-v1")

    # 2. V1.2 case -> report-v1.1
    def test_2_v1_2_case_produces_report_v1_1(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)
        self.assertEqual(report["schema_version"], "report-v1.1")

    # 3. V1.1 output validates against report-v1.json
    def test_3_v1_1_output_validates_against_report_v1_schema(self):
        report = self.engine.generate_report(self.v1_1_case, self.valid_evidence_integrity)
        self.validator.validate("report-v1.json", report)

    # 4. V1.2 output validates against report-v1.1.json
    def test_4_v1_2_output_validates_against_report_v1_1_schema(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)
        self.validator.validate("report-v1.1.json", report)

    # 5. V1.1 output contains no MITRE fields
    def test_5_v1_1_output_contains_no_mitre_fields(self):
        report = self.engine.generate_report(self.v1_1_case, self.valid_evidence_integrity)
        self.assertNotIn("mitre_mappings", report)
        self.assertNotIn("mitre_provenance", report)
        self.assertNotIn("attack_chain", report)

    # 6. V1.2 MITRE mappings preserved exactly
    def test_6_v1_2_mitre_mappings_preserved_exactly(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)
        self.assertIn("mitre_mappings", report)
        self.assertEqual(len(report["mitre_mappings"]), len(self.v1_2_case["mitre_mappings"]))
        mapping = report["mitre_mappings"][0]
        original = self.v1_2_case["mitre_mappings"][0]
        self.assertEqual(mapping["technique_id"], original["technique_id"])
        self.assertEqual(mapping["technique_name"], original["technique_name"])
        self.assertEqual(mapping["tactic_id"], original["tactic_id"])
        self.assertEqual(mapping["tactic_name"], original["tactic_name"])
        self.assertEqual(mapping["behavior_id"], original["behavior_id"])
        self.assertEqual(mapping["mapping_status"], original["mapping_status"])
        self.assertEqual(mapping["mapping_confidence"], original["mapping_confidence"])
        self.assertEqual(mapping["rationale"], original["rationale"])

    # 7. V1.2 MITRE provenance preserved exactly
    def test_7_v1_2_mitre_provenance_preserved_exactly(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)
        self.assertIn("mitre_provenance", report)
        prov = report["mitre_provenance"]
        original = self.v1_2_case["mitre_provenance"]
        self.assertEqual(prov["framework"], original["framework"])
        self.assertEqual(prov["domain"], original["domain"])
        self.assertEqual(prov["version"], original["version"])
        self.assertEqual(prov["knowledge_profile_id"], original["knowledge_profile_id"])

    # 8. V1.2 attack chain preserved exactly
    def test_8_v1_2_attack_chain_preserved_exactly(self):
        case = deepcopy(self.v1_2_case)
        case["attack_chain"] = {
            "status": "potential",
            "stages": [
                {
                    "stage_id": "STG-01",
                    "name": "Initial Access",
                    "timestamp": "2026-08-15T09:45:00Z",
                    "finding_ids": ["finding-001"],
                    "event_ids": ["evt-001"]
                }
            ]
        }
        report = self.engine.generate_report(case, self.valid_evidence_integrity)
        self.assertIn("attack_chain", report)
        ac = report["attack_chain"]
        self.assertEqual(ac["status"], "potential")
        self.assertEqual(len(ac["stages"]), 1)
        stg = ac["stages"][0]
        self.assertEqual(stg["stage_id"], "STG-01")
        self.assertEqual(stg["name"], "Initial Access")

    # 9. MITRE mapping evidence_ids preserved
    def test_9_mitre_mapping_evidence_ids_preserved(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)
        mapping = report["mitre_mappings"][0]
        self.assertEqual(mapping["evidence_ids"], ["ev-001"])

    # 10. MITRE mapping source_finding_ids preserved
    def test_10_mitre_mapping_source_finding_ids_preserved(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)
        mapping = report["mitre_mappings"][0]
        self.assertEqual(mapping["source_finding_ids"], ["finding-001"])

    # 11. Attack-chain stage finding_ids preserved
    def test_11_attack_chain_stage_finding_ids_preserved(self):
        case = deepcopy(self.v1_2_case)
        case["attack_chain"] = {
            "status": "confirmed",
            "stages": [
                {
                    "stage_id": "STG-02",
                    "name": "Exfiltration Stage",
                    "finding_ids": ["finding-001", "finding-002"]
                }
            ]
        }
        report = self.engine.generate_report(case, self.valid_evidence_integrity)
        stg = report["attack_chain"]["stages"][0]
        self.assertEqual(stg["finding_ids"], ["finding-001", "finding-002"])

    # 12. Attack-chain stage event_ids preserved
    def test_12_attack_chain_stage_event_ids_preserved(self):
        case = deepcopy(self.v1_2_case)
        case["attack_chain"] = {
            "status": "confirmed",
            "stages": [
                {
                    "stage_id": "STG-02",
                    "name": "Exfiltration Stage",
                    "event_ids": ["evt-001", "evt-002"]
                }
            ]
        }
        report = self.engine.generate_report(case, self.valid_evidence_integrity)
        stg = report["attack_chain"]["stages"][0]
        self.assertEqual(stg["event_ids"], ["evt-001", "evt-002"])

    # 13. Unsupported case version rejected
    def test_13_unsupported_case_version_rejected(self):
        invalid_case = deepcopy(self.v1_1_case)
        invalid_case["schema_version"] = "investigation-case-v9.9"
        with self.assertRaises(ValueError):
            self.engine.generate_report(invalid_case, self.valid_evidence_integrity)

    # 14. Missing/invalid V1.2 fields rejected by contract
    def test_14_missing_or_invalid_v1_2_fields_rejected(self):
        invalid_case = deepcopy(self.v1_2_case)
        # Invalid confidence value (> 1.0)
        invalid_case["mitre_mappings"][0]["mapping_confidence"] = 5.0
        with self.assertRaises(Exception):
            self.engine.generate_report(invalid_case, self.valid_evidence_integrity)

    # 15. Evidence integrity remains unchanged
    def test_15_evidence_integrity_remains_unchanged(self):
        report = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)
        self.assertIn("evidence_integrity", report)
        self.assertEqual(len(report["evidence_integrity"]), 1)
        rec = report["evidence_integrity"][0]
        self.assertEqual(rec["evidence_id"], "ev-001")
        self.assertEqual(rec["verification_status"], "verified")
        self.assertEqual(report["summary"]["verified_evidence_count"], 1)

    # 16. Report ID remains deterministic
    def test_16_report_id_remains_deterministic(self):
        report1 = self.engine.generate_report(self.v1_1_case, self.valid_evidence_integrity)
        report2 = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)
        self.assertEqual(report1["report_id"], f"RPT-{self.v1_1_case['case_id']}")
        self.assertEqual(report2["report_id"], f"RPT-{self.v1_2_case['case_id']}")

    # 17. Input case is not mutated
    def test_17_input_case_is_not_mutated(self):
        case_copy = deepcopy(self.v1_2_case)
        _ = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)
        self.assertEqual(self.v1_2_case, case_copy)

    # 18. Deterministic output for identical inputs except generated_at
    def test_18_deterministic_output_except_generated_at(self):
        report1 = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)
        report2 = self.engine.generate_report(self.v1_2_case, self.valid_evidence_integrity)

        # Normalize timestamps for comparison
        r1_norm = deepcopy(report1)
        r2_norm = deepcopy(report2)
        r1_norm.pop("generated_at")
        r2_norm.pop("generated_at")

        self.assertEqual(r1_norm, r2_norm)


if __name__ == "__main__":
    unittest.main()
