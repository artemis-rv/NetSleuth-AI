import unittest
import json
from pathlib import Path
from copy import deepcopy

from app.shared.contract_validation import ContractValidator
from app.engines.reporting.report_exporter import ReportExporter


class TestReportExporterVersionAware(unittest.TestCase):
    """
    Comprehensive tests for M4 ReportExporter version-aware support (Report V1 and Report V1.1).
    """

    def setUp(self):
        self.validator = ContractValidator()
        self.exporter = ReportExporter(self.validator)

        fixtures_dir = Path(__file__).resolve().parent.parent.parent.parent / "fixtures"

        # Load Report V1.1 fixture
        v1_1_path = fixtures_dir / "reports" / "report-v1.1-valid.json"
        with open(v1_1_path, "r", encoding="utf-8") as f:
            self.valid_report_v1_1 = json.load(f)

        # Create valid Report V1 fixture
        self.valid_report_v1 = deepcopy(self.valid_report_v1_1)
        self.valid_report_v1["schema_version"] = "report-v1"
        self.valid_report_v1.pop("mitre_mappings", None)
        self.valid_report_v1.pop("mitre_provenance", None)
        self.valid_report_v1.pop("attack_chain", None)

    # 1. Report V1 exports successfully.
    def test_1_report_v1_exports_successfully(self):
        exported = self.exporter.export_json(self.valid_report_v1)
        self.assertIsInstance(exported, str)
        parsed = json.loads(exported)
        self.assertEqual(parsed["schema_version"], "report-v1")

    # 2. Report V1 validates against report-v1.json.
    def test_2_report_v1_validates_against_schema(self):
        exported = self.exporter.export_json(self.valid_report_v1)
        parsed = json.loads(exported)
        self.validator.validate("report-v1.json", parsed)

    # 3. Report V1.1 exports successfully.
    def test_3_report_v1_1_exports_successfully(self):
        exported = self.exporter.export_json(self.valid_report_v1_1)
        self.assertIsInstance(exported, str)
        parsed = json.loads(exported)
        self.assertEqual(parsed["schema_version"], "report-v1.1")

    # 4. Report V1.1 validates against report-v1.1.json.
    def test_4_report_v1_1_validates_against_schema(self):
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.validator.validate("report-v1.1.json", parsed)

    # 5. Report V1.1 MITRE mappings are preserved exactly.
    def test_5_report_v1_1_mitre_mappings_preserved_exactly(self):
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.assertIn("mitre_mappings", parsed)
        self.assertEqual(len(parsed["mitre_mappings"]), len(self.valid_report_v1_1["mitre_mappings"]))
        mapping = parsed["mitre_mappings"][0]
        original = self.valid_report_v1_1["mitre_mappings"][0]
        self.assertEqual(mapping["technique_id"], original["technique_id"])
        self.assertEqual(mapping["technique_name"], original["technique_name"])
        self.assertEqual(mapping["tactic_id"], original["tactic_id"])

    # 6. MITRE provenance is preserved exactly.
    def test_6_mitre_provenance_preserved_exactly(self):
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.assertIn("mitre_provenance", parsed)
        prov = parsed["mitre_provenance"]
        original = self.valid_report_v1_1["mitre_provenance"]
        self.assertEqual(prov["framework"], original["framework"])
        self.assertEqual(prov["domain"], original["domain"])
        self.assertEqual(prov["version"], original["version"])

    # 7. Attack chain is preserved exactly.
    def test_7_attack_chain_preserved_exactly(self):
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.assertIn("attack_chain", parsed)
        ac = parsed["attack_chain"]
        original = self.valid_report_v1_1["attack_chain"]
        self.assertEqual(ac["status"], original["status"])

    # 8. Attack-chain stage finding_ids are preserved.
    def test_8_attack_chain_stage_finding_ids_preserved(self):
        report = deepcopy(self.valid_report_v1_1)
        report["attack_chain"] = {
            "status": "confirmed",
            "stages": [
                {
                    "stage_id": "STG-01",
                    "name": "Exfiltration Stage",
                    "finding_ids": ["FINDING-001", "FINDING-002"]
                }
            ]
        }
        exported = self.exporter.export_json(report)
        parsed = json.loads(exported)
        stage = parsed["attack_chain"]["stages"][0]
        self.assertEqual(stage["finding_ids"], ["FINDING-001", "FINDING-002"])

    # 9. Attack-chain stage event_ids are preserved.
    def test_9_attack_chain_stage_event_ids_preserved(self):
        report = deepcopy(self.valid_report_v1_1)
        report["attack_chain"] = {
            "status": "confirmed",
            "stages": [
                {
                    "stage_id": "STG-01",
                    "name": "Exfiltration Stage",
                    "event_ids": ["EVT-001", "EVT-002"]
                }
            ]
        }
        exported = self.exporter.export_json(report)
        parsed = json.loads(exported)
        stage = parsed["attack_chain"]["stages"][0]
        self.assertEqual(stage["event_ids"], ["EVT-001", "EVT-002"])

    # 10. Evidence integrity is preserved.
    def test_10_evidence_integrity_preserved(self):
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.assertIn("evidence_integrity", parsed)
        self.assertEqual(len(parsed["evidence_integrity"]), len(self.valid_report_v1_1["evidence_integrity"]))
        rec = parsed["evidence_integrity"][0]
        original = self.valid_report_v1_1["evidence_integrity"][0]
        self.assertEqual(rec["evidence_id"], original["evidence_id"])
        self.assertEqual(rec["verification_status"], original["verification_status"])

    # 11. Chain of custody is preserved.
    def test_11_chain_of_custody_preserved(self):
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        rec = parsed["evidence_integrity"][0]
        self.assertIn("chain_of_custody", rec)
        original_custody = self.valid_report_v1_1["evidence_integrity"][0]["chain_of_custody"]
        self.assertEqual(rec["chain_of_custody"], original_custody)

    # 12. Unsupported report schema is rejected.
    def test_12_unsupported_report_schema_rejected(self):
        invalid_report = deepcopy(self.valid_report_v1_1)
        invalid_report["schema_version"] = "report-v2.0"
        with self.assertRaises(ValueError):
            self.exporter.export_json(invalid_report)

    # 13. Invalid Report V1.1 payload is rejected.
    def test_13_invalid_report_v1_1_payload_rejected(self):
        invalid_report = deepcopy(self.valid_report_v1_1)
        invalid_report["mitre_mappings"][0]["mapping_confidence"] = 2.5 # invalid confidence (> 1.0)
        with self.assertRaises(Exception):
            self.exporter.export_json(invalid_report)

    # 14. Input dictionary is not mutated.
    def test_14_input_dictionary_not_mutated(self):
        original = deepcopy(self.valid_report_v1_1)
        _ = self.exporter.export_json(self.valid_report_v1_1)
        self.assertEqual(self.valid_report_v1_1, original)

    # 15. Output is deterministic.
    def test_15_output_is_deterministic(self):
        exp1 = self.exporter.export_json(self.valid_report_v1_1)
        exp2 = self.exporter.export_json(self.valid_report_v1_1)
        self.assertEqual(exp1, exp2)

    # 16. Unicode is preserved.
    def test_16_unicode_is_preserved(self):
        report = deepcopy(self.valid_report_v1_1)
        report["summary"]["case_description"] = "Investigación de exfiltración — Network Sleuth AI"
        exported = self.exporter.export_json(report)
        self.assertIn("Investigación de exfiltración — Network Sleuth AI", exported)

    # 17. No fields are added.
    def test_17_no_fields_are_added(self):
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        self.assertEqual(set(parsed.keys()), set(self.valid_report_v1_1.keys()))

    # 18. No fields are removed.
    def test_18_no_fields_are_removed(self):
        exported = self.exporter.export_json(self.valid_report_v1_1)
        parsed = json.loads(exported)
        for key in self.valid_report_v1_1.keys():
            self.assertIn(key, parsed)


if __name__ == "__main__":
    unittest.main()
