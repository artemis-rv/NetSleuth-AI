import unittest
import json
from pathlib import Path
from copy import deepcopy

try:
    from backend.app.shared.contract_validation import ContractValidator
except ImportError:
    from src.shared.contract_validation import ContractValidator

class TestReportV11Contract(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()

        fixture_path = (
            Path(__file__).resolve().parent.parent.parent.parent
            / "fixtures"
            / "reports"
            / "report-v1.1-valid.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.valid_v1_1_fixture = json.load(f)

    def test_1_valid_report_v1_1_fixture_validates(self):
        """1. Valid Report V1.1 fixture validates against report-v1.1.json."""
        self.validator.validate("report-v1.1.json", self.valid_v1_1_fixture)

    def test_2_schema_version_is_enforced(self):
        """2. schema_version = 'report-v1.1' is enforced."""
        invalid_version = deepcopy(self.valid_v1_1_fixture)
        invalid_version["schema_version"] = "report-v1.0"
        with self.assertRaises(Exception):
            self.validator.validate("report-v1.1.json", invalid_version)

    def test_3_missing_required_fields_fail(self):
        """3. Missing required fields fail validation."""
        missing_case_id = deepcopy(self.valid_v1_1_fixture)
        del missing_case_id["case_id"]
        with self.assertRaises(Exception):
            self.validator.validate("report-v1.1.json", missing_case_id)

        missing_summary = deepcopy(self.valid_v1_1_fixture)
        del missing_summary["summary"]
        with self.assertRaises(Exception):
            self.validator.validate("report-v1.1.json", missing_summary)

    def test_4_invalid_enums_fail(self):
        """4. Invalid enums in findings or attack chain status fail validation."""
        invalid_sev = deepcopy(self.valid_v1_1_fixture)
        invalid_sev["findings"][0]["severity"] = "INVALID_SEVERITY"
        with self.assertRaises(Exception):
            self.validator.validate("report-v1.1.json", invalid_sev)

        invalid_ac_status = deepcopy(self.valid_v1_1_fixture)
        invalid_ac_status["attack_chain"]["status"] = "INVALID_STATUS"
        with self.assertRaises(Exception):
            self.validator.validate("report-v1.1.json", invalid_ac_status)

    def test_5_additional_properties_false_is_enforced(self):
        """5. additionalProperties=false is enforced at root and nested levels."""
        extra_root = deepcopy(self.valid_v1_1_fixture)
        extra_root["uncontracted_root_field"] = "value"
        with self.assertRaises(Exception):
            self.validator.validate("report-v1.1.json", extra_root)

        extra_mapping = deepcopy(self.valid_v1_1_fixture)
        extra_mapping["mitre_mappings"][0]["extra_prop"] = "invalid"
        with self.assertRaises(Exception):
            self.validator.validate("report-v1.1.json", extra_mapping)

    def test_6_existing_v1_fields_remain_valid(self):
        """6. Existing V1 fields remain preserved and valid."""
        report = deepcopy(self.valid_v1_1_fixture)
        self.assertEqual(report["report_id"], "RPT-CASE-SCENARIO-001")
        self.assertEqual(report["summary"]["total_findings"], 1)
        self.assertEqual(len(report["findings"]), 1)
        self.assertEqual(len(report["timeline"]), 2)
        self.assertEqual(len(report["entities"]), 1)
        self.assertEqual(len(report["relationships"]), 1)
        self.validator.validate("report-v1.1.json", report)

    def test_7_mitre_mappings_validate(self):
        """7. MITRE mappings with technique_id, tactic, confidence validate."""
        report = deepcopy(self.valid_v1_1_fixture)
        mapping = report["mitre_mappings"][0]
        self.assertEqual(mapping["technique_id"], "T1071.004")
        self.assertEqual(mapping["mapping_status"], "SUPPORTED")
        self.assertEqual(mapping["mapping_confidence"], 0.95)
        self.validator.validate("report-v1.1.json", report)

    def test_8_mitre_provenance_validates(self):
        """8. MITRE provenance validates."""
        report = deepcopy(self.valid_v1_1_fixture)
        prov = report["mitre_provenance"]
        self.assertEqual(prov["framework"], "ATT&CK")
        self.assertEqual(prov["domain"], "Enterprise")
        self.assertEqual(prov["version"], "v14.1")
        self.validator.validate("report-v1.1.json", report)

    def test_9_attack_chain_validates(self):
        """9. Attack chain status and stages validate."""
        report = deepcopy(self.valid_v1_1_fixture)
        ac = report["attack_chain"]
        self.assertEqual(ac["status"], "potential")
        self.assertEqual(ac["stages"][0]["stage_id"], "STG-01")
        self.validator.validate("report-v1.1.json", report)

    def test_10_evidence_integrity_remains_preserved(self):
        """10. Evidence integrity records remain preserved."""
        report = deepcopy(self.valid_v1_1_fixture)
        ev_rec = report["evidence_integrity"][0]
        self.assertEqual(ev_rec["evidence_id"], "ev-FLOW-001")
        self.assertEqual(ev_rec["verification_status"], "verified")
        self.assertEqual(ev_rec["expected_hash"], ev_rec["calculated_hash"])

    def test_11_chain_of_custody_remains_preserved(self):
        """11. Chain of custody log remains preserved."""
        report = deepcopy(self.valid_v1_1_fixture)
        custody = report["evidence_integrity"][0]["chain_of_custody"]
        self.assertEqual(len(custody), 2)
        self.assertEqual(custody[0]["action"], "ingest")
        self.assertEqual(custody[1]["action"], "verify")

    def test_12_case_id_remains_preserved(self):
        """12. Case ID remains preserved across root and evidence integrity records."""
        report = deepcopy(self.valid_v1_1_fixture)
        self.assertEqual(report["case_id"], "CASE-SCENARIO-001")
        for rec in report["evidence_integrity"]:
            self.assertEqual(rec["case_id"], "CASE-SCENARIO-001")

    def test_13_deterministic_serialization_works(self):
        """13. Deterministic JSON serialization round-trip works."""
        s1 = json.dumps(self.valid_v1_1_fixture, sort_keys=True, indent=2)
        reloaded = json.loads(s1)
        s2 = json.dumps(reloaded, sort_keys=True, indent=2)
        self.assertEqual(s1, s2)
        self.validator.validate("report-v1.1.json", reloaded)

    def test_14_no_undocumented_fields_are_accepted(self):
        """14. No undocumented/uncontracted MITRE or attack chain fields are accepted."""
        invented_field = deepcopy(self.valid_v1_1_fixture)
        invented_field["attack_chain"]["invented_threat_score"] = 100
        with self.assertRaises(Exception):
            self.validator.validate("report-v1.1.json", invented_field)

if __name__ == "__main__":
    unittest.main()
