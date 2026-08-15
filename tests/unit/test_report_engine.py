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

    def test_1_valid_scenario_001_report_generation(self):
        """Verify report generation from Scenario 001 produces valid Report V1."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(report["schema_version"], "report-v1")
        self.assertEqual(report["case_id"], self.sample_case["case_id"])
        self.assertEqual(report["report_id"], f"RPT-{self.sample_case['case_id']}")

    def test_2_report_schema_validation(self):
        """Verify generated report passes contract schema validation."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.validator.validate("report-v1.json", report)

    def test_3_deterministic_report_id(self):
        """Verify report_id is deterministically derived as RPT-{case_id}."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(report["report_id"], f"RPT-{self.sample_case['case_id']}")

    def test_4_finding_preservation(self):
        """Verify M3 findings are projected into contract-compliant ReportFinding representations."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(len(report["findings"]), len(self.sample_case["findings"]))
        for i, f in enumerate(report["findings"]):
            src = self.sample_case["findings"][i]
            self.assertEqual(f["finding_id"], src["finding_id"])

    def test_5_timeline_preservation(self):
        """Verify M3 timeline events are projected into contract-compliant ReportTimelineEvent representations."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(len(report["timeline"]), len(self.sample_case["timeline"]))
        for i, te in enumerate(report["timeline"]):
            src = self.sample_case["timeline"][i]
            self.assertEqual(te["event_id"], src["event_id"])
            self.assertEqual(te["timestamp"], src["timestamp"])

    def test_6_entity_preservation(self):
        """Verify M3 entities are projected into contract-compliant ReportEntity representations."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(len(report["entities"]), len(self.sample_case["entities"]))
        for i, e in enumerate(report["entities"]):
            src = self.sample_case["entities"][i]
            self.assertEqual(e["entity_id"], src["entity_id"])
            self.assertEqual(e["entity_type"], src["entity_type"])

    def test_7_relationship_preservation(self):
        """Verify M3 relationships are preserved verbatim in report."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        self.assertEqual(report["relationships"], self.sample_case["relationships"])

    def test_8_evidence_preservation(self):
        """Verify evidence integrity records are preserved in report."""
        records = [self.sample_evidence_record]
        report = self.engine.generate_report(self.sample_case, records)
        self.assertEqual(report["evidence_integrity"], records)

    def test_9_evidence_counter_calculation(self):
        """Verify summary evidence counters calculate verified, mismatched, unverified counts correctly."""
        records = [deepcopy(self.sample_evidence_record)]
        records[0]["verification_status"] = "verified"
        report = self.engine.generate_report(self.sample_case, records)
        summary = report["summary"]
        self.assertEqual(summary["total_evidence_references"], 1)
        self.assertEqual(summary["verified_evidence_count"], 1)
        self.assertEqual(summary["mismatched_evidence_count"], 0)
        self.assertEqual(summary["unverified_evidence_count"], 0)

    def test_10_duplicate_evidence_id_handling(self):
        """Verify duplicate identical evidence records are deduplicated in summary counters."""
        records = [deepcopy(self.sample_evidence_record), deepcopy(self.sample_evidence_record)]
        report = self.engine.generate_report(self.sample_case, records)
        self.assertEqual(report["summary"]["total_evidence_references"], 1)

    def test_11_unverified_evidence_handling(self):
        """Verify unverified status increments unverified_evidence_count."""
        rec = deepcopy(self.sample_evidence_record)
        rec["verification_status"] = "unverified"
        report = self.engine.generate_report(self.sample_case, [rec])
        self.assertEqual(report["summary"]["unverified_evidence_count"], 1)
        self.assertEqual(report["summary"]["verified_evidence_count"], 0)

    def test_12_mismatched_evidence_handling(self):
        """Verify mismatch status increments mismatched_evidence_count."""
        rec = deepcopy(self.sample_evidence_record)
        rec["verification_status"] = "mismatch"
        report = self.engine.generate_report(self.sample_case, [rec])
        self.assertEqual(report["summary"]["mismatched_evidence_count"], 1)
        self.assertEqual(report["summary"]["verified_evidence_count"], 0)

    def test_13_missing_evidence_rejection(self):
        """Verify non-list/non-package evidence input raises ValueError."""
        with self.assertRaises(ValueError):
            self.engine.generate_report(self.sample_case, "invalid_evidence_input")

    def test_14_invalid_investigation_case_rejection(self):
        """Verify malformed InvestigationCase payload raises ValueError or ValidationError."""
        bad_case = deepcopy(self.sample_case)
        del bad_case["case_id"]
        with self.assertRaises(Exception):
            self.engine.generate_report(bad_case, [self.sample_evidence_record])

    def test_15_invalid_evidence_integrity_rejection(self):
        """Verify malformed EvidenceIntegrity record raises ValidationError."""
        bad_record = deepcopy(self.sample_evidence_record)
        bad_record["verification_status"] = "invalid_status"
        with self.assertRaises(Exception):
            self.engine.generate_report(self.sample_case, [bad_record])

    def test_16_generated_at_is_utc_aware(self):
        """Verify generated_at timestamp is valid UTC ISO-8601 string."""
        report = self.engine.generate_report(self.sample_case, self.sample_package)
        ts_str = report["generated_at"]
        self.assertIn("Z", ts_str)
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        self.assertIsNotNone(dt.tzinfo)

    def test_17_input_immutability(self):
        """Verify input case dict and evidence records are not mutated during report generation."""
        case_copy = deepcopy(self.sample_case)
        record_copy = deepcopy(self.sample_evidence_record)

        self.engine.generate_report(self.sample_case, [self.sample_evidence_record])

        self.assertEqual(self.sample_case, case_copy)
        self.assertEqual(self.sample_evidence_record, record_copy)

    def test_18_repeated_generation_determinism_except_generated_at(self):
        """Verify repeated calls produce identical report structure except for generated_at timestamp."""
        r1 = self.engine.generate_report(self.sample_case, [self.sample_evidence_record])
        r2 = self.engine.generate_report(self.sample_case, [self.sample_evidence_record])

        self.assertEqual(r1["report_id"], r2["report_id"])
        self.assertEqual(r1["case_id"], r2["case_id"])
        self.assertEqual(r1["summary"], r2["summary"])
        self.assertEqual(r1["findings"], r2["findings"])
        self.assertEqual(r1["timeline"], r2["timeline"])
        self.assertEqual(r1["evidence_integrity"], r2["evidence_integrity"])
