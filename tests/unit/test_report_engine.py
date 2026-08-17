import unittest
import json
from pathlib import Path
from copy import deepcopy
from datetime import datetime

from src.shared.contract_validation import ContractValidator
from src.m4_evidence.evidence_package import M4EvidencePackageBuilder
from src.m4_evidence.report_engine import ReportEngine

class TestReportEngine(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.package_builder = M4EvidencePackageBuilder(self.validator)
        self.engine = ReportEngine(self.validator)

        fixture_case_path = (
            Path(__file__).resolve().parent.parent.parent
            / "fixtures"
            / "investigations"
            / "investigation-case-v1-scenario-001-expected.json"
        )
        with open(fixture_case_path, "r", encoding="utf-8") as f:
            self.sample_case = json.load(f)

        fixture_ev_path = (
            Path(__file__).resolve().parent.parent.parent
            / "fixtures"
            / "evidence"
            / "evidence-integrity-v1-valid.json"
        )
        with open(fixture_ev_path, "r", encoding="utf-8") as f:
            self.sample_evidence_record = json.load(f)

        self.sample_package = self.package_builder.build(self.sample_case)

        # Standard V1.2 case fixture
        self.sample_case_v1_2 = {
            "schema_version": "investigation-case-v1.2",
            "case_id": "CASE-TEST-V1-2",
            "title": "Test Investigation Case V1.2",
            "description": "Case with MITRE ATT&CK mappings and attack chain",
            "status": "open",
            "severity": "high",
            "created_at": "2026-08-15T10:00:00Z",
            "updated_at": "2026-08-15T12:00:00Z",
            "investigator": {
                "investigator_id": "inv-1",
                "name": "Analyst Alice"
            },
            "timeline": [
                {
                    "event_id": "EVT-001",
                    "timestamp": "2026-08-15T10:05:00Z",
                    "event_type": "network",
                    "description": "Web traffic detected",
                    "evidence_ids": ["ev-FLOW-001"]
                }
            ],
            "entities": [
                {
                    "entity_id": "ent-IP-001",
                    "entity_type": "ip",
                    "label": "192.168.1.105"
                }
            ],
            "relationships": [
                {
                    "relationship_id": "REL-001",
                    "source_entity_id": "ent-IP-001",
                    "target_entity_id": "ent-DOMAIN-001",
                    "relationship_type": "queried",
                    "confidence": 0.9,
                    "evidence_ids": ["ev-FLOW-001"]
                }
            ],
            "evidence_references": [
                {
                    "evidence_id": "ev-FLOW-001",
                    "evidence_type": "flow",
                    "source_id": "FLOW-001"
                }
            ],
            "findings": [
                {
                    "finding_id": "FINDING-DNS-001",
                    "role": "primary"
                }
            ],
            "mitre_provenance": {
                "framework": "ATT&CK",
                "domain": "Enterprise",
                "version": "v14.1",
                "knowledge_profile_id": "kp-enterprise-v14.1"
            },
            "mitre_mappings": [
                {
                    "technique_id": "T1071.004",
                    "technique_name": "DNS",
                    "tactic_id": "TA0011",
                    "tactic_name": "Command and Control",
                    "behavior_id": "C2 / DNS Tunneling",
                    "mapping_status": "SUPPORTED",
                    "mapping_confidence": 0.95,
                    "rationale": "High-volume entropy TXT queries matching C2 profile",
                    "source_finding_ids": ["FINDING-DNS-001"],
                    "evidence_ids": ["ev-FLOW-001"],
                    "first_seen": "2026-08-15T10:00:00Z",
                    "last_seen": "2026-08-15T10:05:00Z",
                    "detection_strategy_ids": ["DS-DNS-001"],
                    "analytic_ids": ["AN-DNS-001"],
                    "data_component_ids": ["DC-DNS-001"],
                    "channels": ["dns"]
                }
            ],
            "attack_chain": {
                "status": "potential",
                "stages": [
                    {
                        "stage_id": "STG-01",
                        "name": "Command and Control",
                        "timestamp": "2026-08-15T10:00:00Z",
                        "event_ids": ["EVT-001"],
                        "finding_ids": ["FINDING-DNS-001"]
                    }
                ]
            }
        }
        self.sample_package_v1_2 = self.package_builder.build(self.sample_case_v1_2)

    def test_1_valid_scenario_001_report_generation(self):
        """1. Verify V1.1 InvestigationCase produces valid Report V1."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(report["schema_version"], "report-v1")
        self.assertEqual(report["case_id"], self.sample_case["case_id"])
        self.assertEqual(report["report_id"], f"RPT-{self.sample_case['case_id']}")

    def test_2_report_schema_validation(self):
        """2. Verify generated V1 report passes report-v1.json contract schema validation."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.validator.validate("report-v1.json", report)

    def test_3_deterministic_report_id(self):
        """3. Verify report_id is deterministically derived as RPT-{case_id}."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(report["report_id"], f"RPT-{self.sample_case['case_id']}")

    def test_4_finding_preservation(self):
        """4. Verify M3 findings are projected into contract-compliant ReportFinding representations."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(len(report["findings"]), len(self.sample_case["findings"]))
        for i, f in enumerate(report["findings"]):
            src = self.sample_case["findings"][i]
            self.assertEqual(f["finding_id"], src["finding_id"])

    def test_5_timeline_preservation(self):
        """5. Verify M3 timeline events are projected into contract-compliant ReportTimelineEvent representations."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(len(report["timeline"]), len(self.sample_case["timeline"]))
        for i, te in enumerate(report["timeline"]):
            src = self.sample_case["timeline"][i]
            self.assertEqual(te["event_id"], src["event_id"])
            self.assertEqual(te["timestamp"], src["timestamp"])

    def test_6_entity_preservation(self):
        """6. Verify M3 entities are projected into contract-compliant ReportEntity representations."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(len(report["entities"]), len(self.sample_case["entities"]))
        for i, e in enumerate(report["entities"]):
            src = self.sample_case["entities"][i]
            self.assertEqual(e["entity_id"], src["entity_id"])
            self.assertEqual(e["entity_type"], src["entity_type"])

    def test_7_relationship_preservation(self):
        """7. Verify M3 relationships are preserved verbatim in report."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(report["relationships"], self.sample_case["relationships"])

    def test_8_evidence_preservation(self):
        """8. Verify evidence integrity records are preserved in report."""
        records = [self.sample_evidence_record]
        report = self.engine.generate_report(self.sample_case, records)
        self.assertEqual(report["evidence_integrity"], records)

    def test_9_evidence_counter_calculation(self):
        """9. Verify summary evidence counters calculate verified, mismatched, unverified counts correctly."""
        records = [deepcopy(self.sample_evidence_record)]
        records[0]["verification_status"] = "verified"
        report = self.engine.generate_report(self.sample_case, records)
        summary = report["summary"]
        self.assertEqual(summary["total_evidence_references"], 1)
        self.assertEqual(summary["verified_evidence_count"], 1)
        self.assertEqual(summary["mismatched_evidence_count"], 0)
        self.assertEqual(summary["unverified_evidence_count"], 0)

    def test_10_duplicate_evidence_id_handling(self):
        """10. Verify duplicate identical evidence records are deduplicated in summary counters."""
        records = [deepcopy(self.sample_evidence_record), deepcopy(self.sample_evidence_record)]
        report = self.engine.generate_report(self.sample_case, records)
        self.assertEqual(report["summary"]["total_evidence_references"], 1)

    def test_11_unverified_evidence_handling(self):
        """11. Verify unverified status increments unverified_evidence_count."""
        rec = deepcopy(self.sample_evidence_record)
        rec["verification_status"] = "unverified"
        report = self.engine.generate_report(self.sample_case, [rec])
        self.assertEqual(report["summary"]["unverified_evidence_count"], 1)
        self.assertEqual(report["summary"]["verified_evidence_count"], 0)

    def test_12_mismatched_evidence_handling(self):
        """12. Verify mismatch status increments mismatched_evidence_count."""
        rec = deepcopy(self.sample_evidence_record)
        rec["verification_status"] = "mismatch"
        report = self.engine.generate_report(self.sample_case, [rec])
        self.assertEqual(report["summary"]["mismatched_evidence_count"], 1)
        self.assertEqual(report["summary"]["verified_evidence_count"], 0)

    def test_13_missing_evidence_rejection(self):
        """13. Verify non-list/non-package evidence input raises ValueError."""
        with self.assertRaises(ValueError):
            self.engine.generate_report(self.sample_case, "invalid_evidence_input")

    def test_14_invalid_investigation_case_rejection(self):
        """14. Verify malformed InvestigationCase payload raises ValueError or ValidationError."""
        bad_case = deepcopy(self.sample_case)
        del bad_case["case_id"]
        with self.assertRaises(Exception):
            self.engine.generate_report(bad_case, [self.sample_evidence_record])

    def test_15_invalid_evidence_integrity_rejection(self):
        """15. Verify malformed EvidenceIntegrity record raises ValidationError."""
        bad_record = deepcopy(self.sample_evidence_record)
        bad_record["verification_status"] = "invalid_status"
        with self.assertRaises(Exception):
            self.engine.generate_report(self.sample_case, [bad_record])

    def test_16_generated_at_is_utc_aware(self):
        """16. Verify generated_at timestamp is valid UTC ISO-8601 string."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        ts_str = report["generated_at"]
        self.assertIn("Z", ts_str)
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        self.assertIsNotNone(dt.tzinfo)

    def test_17_input_immutability(self):
        """17. Verify input case dict and evidence records are not mutated during report generation."""
        case_copy = deepcopy(self.sample_case)
        record_copy = deepcopy(self.sample_evidence_record)

        self.engine.generate_report(self.sample_case, [self.sample_evidence_record])

        self.assertEqual(self.sample_case, case_copy)
        self.assertEqual(self.sample_evidence_record, record_copy)

    def test_18_repeated_generation_determinism_except_generated_at(self):
        """18. Verify repeated calls produce identical report structure except for generated_at timestamp."""
        r1 = self.engine.generate_report(self.sample_case, [self.sample_evidence_record])
        r2 = self.engine.generate_report(self.sample_case, [self.sample_evidence_record])

        self.assertEqual(r1["report_id"], r2["report_id"])
        self.assertEqual(r1["case_id"], r2["case_id"])
        self.assertEqual(r1["summary"], r2["summary"])
        self.assertEqual(r1["findings"], r2["findings"])
        self.assertEqual(r1["timeline"], r2["timeline"])
        self.assertEqual(r1["evidence_integrity"], r2["evidence_integrity"])

    def test_19_v1_2_case_produces_report_v1_1(self):
        """19. Verify V1.2 InvestigationCase produces valid Report V1.1 output."""
        report = self.engine.generate_report(self.sample_case_v1_2, self.sample_package_v1_2)
        self.assertEqual(report["schema_version"], "report-v1.1")
        self.assertEqual(report["case_id"], self.sample_case_v1_2["case_id"])
        self.assertEqual(report["report_id"], f"RPT-{self.sample_case_v1_2['case_id']}")
        self.validator.validate("report-v1.1.json", report)

    def test_20_v1_output_does_not_contain_mitre_fields(self):
        """20. Verify V1 Report output does NOT contain MITRE fields."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(report["schema_version"], "report-v1")
        self.assertNotIn("mitre_mappings", report)
        self.assertNotIn("mitre_provenance", report)
        self.assertNotIn("attack_chain", report)

    def test_21_v1_1_preserves_mitre_fields(self):
        """21. Verify V1.1 Report preserves mitre_mappings, mitre_provenance, and attack_chain."""
        report = self.engine.generate_report(self.sample_case_v1_2, self.sample_package_v1_2)
        self.assertIn("mitre_mappings", report)
        self.assertIn("mitre_provenance", report)
        self.assertIn("attack_chain", report)

        self.assertEqual(
            report["mitre_mappings"][0]["technique_id"],
            self.sample_case_v1_2["mitre_mappings"][0]["technique_id"]
        )
        self.assertEqual(
            report["mitre_provenance"]["version"],
            self.sample_case_v1_2["mitre_provenance"]["version"]
        )
        self.assertEqual(
            report["attack_chain"]["status"],
            self.sample_case_v1_2["attack_chain"]["status"]
        )

    def test_22_unknown_schema_version_rejected(self):
        """22. Verify unknown InvestigationCase schema_version is rejected."""
        unknown_case = deepcopy(self.sample_case)
        unknown_case["schema_version"] = "investigation-case-v99.9"
        with self.assertRaises(ValueError):
            self.engine.generate_report(unknown_case, self.sample_package)

    def test_23_invalid_v1_2_case_rejected(self):
        """23. Verify malformed V1.2 InvestigationCase payload is rejected."""
        bad_v1_2 = deepcopy(self.sample_case_v1_2)
        bad_v1_2["mitre_mappings"][0]["mapping_confidence"] = 999.0  # Out of range 0..1
        with self.assertRaises(Exception):
            self.engine.generate_report(bad_v1_2, self.sample_package_v1_2)

if __name__ == "__main__":
    unittest.main()
