import unittest
import json
from pathlib import Path
from copy import deepcopy

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.reporting.report_exporter import ReportExporter

class TestReportExporter(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.exporter = ReportExporter(self.validator)

        fixture_path = (
            Path(__file__).resolve().parent.parent.parent.parent / "fixtures"
            / "reports"
            / "report-v1-valid.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.valid_report = json.load(f)

    def test_1_valid_report_v1_export(self):
        """Verify valid Report V1 dict is exported as JSON string."""
        exported = self.exporter.export_json(self.valid_report)
        self.assertIsInstance(exported, str)
        reloaded = json.loads(exported)
        self.assertEqual(reloaded["schema_version"], "report-v1")

    def test_2_invalid_report_v1_rejection(self):
        """Verify non-dict report input raises ValueError."""
        with self.assertRaises(ValueError):
            self.exporter.export_json("invalid_input_str")

    def test_3_missing_required_field_rejection(self):
        """Verify report with missing required field raises ValidationError."""
        bad_report = deepcopy(self.valid_report)
        del bad_report["case_id"]
        with self.assertRaises(Exception):
            self.exporter.export_json(bad_report)

    def test_4_invalid_enum_rejection(self):
        """Verify invalid severity enum in finding raises ValidationError."""
        bad_report = deepcopy(self.valid_report)
        bad_report["findings"][0]["severity"] = "super_critical"
        with self.assertRaises(Exception):
            self.exporter.export_json(bad_report)

    def test_5_exact_report_id_preservation(self):
        """Verify report_id is preserved verbatim in exported JSON."""
        exported = self.exporter.export_json(self.valid_report)
        reloaded = json.loads(exported)
        self.assertEqual(reloaded["report_id"], self.valid_report["report_id"])

    def test_6_exact_case_id_preservation(self):
        """Verify case_id is preserved verbatim in exported JSON."""
        exported = self.exporter.export_json(self.valid_report)
        reloaded = json.loads(exported)
        self.assertEqual(reloaded["case_id"], self.valid_report["case_id"])

    def test_7_evidence_integrity_preservation(self):
        """Verify evidence integrity records are preserved verbatim in exported JSON."""
        exported = self.exporter.export_json(self.valid_report)
        reloaded = json.loads(exported)
        self.assertEqual(reloaded["evidence_integrity"], self.valid_report["evidence_integrity"])

    def test_8_chain_of_custody_preservation(self):
        """Verify chain of custody entries are preserved verbatim in exported JSON."""
        exported = self.exporter.export_json(self.valid_report)
        reloaded = json.loads(exported)
        custody = reloaded["evidence_integrity"][0]["chain_of_custody"]
        self.assertEqual(custody, self.valid_report["evidence_integrity"][0]["chain_of_custody"])

    def test_9_finding_preservation(self):
        """Verify findings are preserved verbatim in exported JSON."""
        exported = self.exporter.export_json(self.valid_report)
        reloaded = json.loads(exported)
        self.assertEqual(reloaded["findings"], self.valid_report["findings"])

    def test_10_timeline_preservation(self):
        """Verify timeline events are preserved verbatim in exported JSON."""
        exported = self.exporter.export_json(self.valid_report)
        reloaded = json.loads(exported)
        self.assertEqual(reloaded["timeline"], self.valid_report["timeline"])

    def test_11_relationship_preservation(self):
        """Verify relationships are preserved verbatim in exported JSON."""
        exported = self.exporter.export_json(self.valid_report)
        reloaded = json.loads(exported)
        self.assertEqual(reloaded["relationships"], self.valid_report["relationships"])

    def test_12_deterministic_output_across_repeated_exports(self):
        """Verify repeated exports on identical report yield identical JSON string."""
        exp1 = self.exporter.export_json(self.valid_report)
        exp2 = self.exporter.export_json(self.valid_report)
        self.assertEqual(exp1, exp2)

    def test_13_input_immutability(self):
        """Verify input report dict is not mutated during export."""
        report_copy = deepcopy(self.valid_report)
        self.exporter.export_json(self.valid_report)
        self.assertEqual(self.valid_report, report_copy)

    def test_14_no_additional_fields_introduced(self):
        """Verify export does not introduce uncontracted fields."""
        exported = self.exporter.export_json(self.valid_report)
        reloaded = json.loads(exported)
        self.assertEqual(set(reloaded.keys()), set(self.valid_report.keys()))

    def test_15_unicode_content_preservation(self):
        """Verify Unicode/UTF-8 characters in title or description are preserved verbatim."""
        report_unicode = deepcopy(self.valid_report)
        report_unicode["summary"]["case_title"] = "DNS Tunneling Exfiltration: 🔬 🔍 🛡️ NetSleuth"
        exported = self.exporter.export_json(report_unicode)
        self.assertIn("🔬 🔍 🛡️ NetSleuth", exported)
        reloaded = json.loads(exported)
        self.assertEqual(reloaded["summary"]["case_title"], "DNS Tunneling Exfiltration: 🔬 🔍 🛡️ NetSleuth")
