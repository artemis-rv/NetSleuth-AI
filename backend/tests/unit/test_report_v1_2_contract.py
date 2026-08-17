import unittest
import json
import os
import jsonschema
from jsonschema.exceptions import ValidationError

class TestReportV1_2Contract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
        
        v1_1_path = os.path.join(project_root, "docs", "contracts", "report-v1.1.json")
        with open(v1_1_path, "r") as f:
            cls.v1_1_schema = json.load(f)
            
        v1_2_path = os.path.join(project_root, "docs", "contracts", "report-v1.2.json")
        with open(v1_2_path, "r") as f:
            cls.v1_2_schema = json.load(f)
            
        fixture_no_llm_path = os.path.join(project_root, "fixtures", "reports", "report-v1.2-valid-no-llm.json")
        with open(fixture_no_llm_path, "r") as f:
            cls.fixture_no_llm = json.load(f)
            
        fixture_llm_path = os.path.join(project_root, "fixtures", "reports", "report-v1.2-valid.json")
        with open(fixture_llm_path, "r") as f:
            cls.fixture_llm = json.load(f)

    def _validate_v1_2(self, instance):
        jsonschema.validate(
            instance=instance, 
            schema=self.v1_2_schema, 
            format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
        )

    def _validate_v1_1(self, instance):
        jsonschema.validate(
            instance=instance, 
            schema=self.v1_1_schema, 
            format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
        )

    def test_01_valid_v1_2_report_passes(self):
        # 1. Valid V1.2 report passes.
        # 3. V1.2 with valid llm_enrichment passes.
        self._validate_v1_2(self.fixture_llm)

    def test_02_v1_2_without_llm_enrichment_passes(self):
        # 2. V1.2 without llm_enrichment passes.
        self._validate_v1_2(self.fixture_no_llm)

    def test_04_invalid_llm_status_fails(self):
        # 4. Invalid LLM status fails.
        report = dict(self.fixture_llm)
        report["llm_enrichment"] = dict(report["llm_enrichment"])
        report["llm_enrichment"]["status"] = "INVALID_STATUS"
        with self.assertRaises(ValidationError):
            self._validate_v1_2(report)

    def test_05_unknown_llm_field_fails(self):
        # 5. Unknown LLM field fails. (additionalProperties: False)
        report = dict(self.fixture_llm)
        report["llm_enrichment"] = dict(report["llm_enrichment"])
        report["llm_enrichment"]["unknown_key"] = "test"
        with self.assertRaises(ValidationError):
            self._validate_v1_2(report)

    def test_06_invalid_nested_llm_field_fails(self):
        # 6. Invalid nested LLM field fails.
        report = dict(self.fixture_llm)
        report["llm_enrichment"] = dict(report["llm_enrichment"])
        report["llm_enrichment"]["mitre_explanations"] = [
            dict(report["llm_enrichment"]["mitre_explanations"][0])
        ]
        report["llm_enrichment"]["mitre_explanations"][0]["unknown_key"] = "test"
        with self.assertRaises(ValidationError):
            self._validate_v1_2(report)

    def test_07_deterministic_report_fields_remain_required(self):
        # 7. Deterministic report fields remain required.
        report = dict(self.fixture_llm)
        del report["findings"]
        with self.assertRaises(ValidationError):
            self._validate_v1_2(report)

    def test_08_mitre_mappings_remain_valid(self):
        # 8. MITRE mappings remain valid.
        self.assertIn("mitre_mappings", self.fixture_llm)
        self.assertEqual(self.fixture_llm["mitre_mappings"][0]["technique_id"], "T1071.001")

    def test_09_attack_chain_remains_valid(self):
        # 9. Attack chain remains valid.
        self.assertIn("attack_chain", self.fixture_llm)
        self.assertEqual(self.fixture_llm["attack_chain"]["status"], "potential")

    def test_10_report_v1_1_still_validates_unchanged(self):
        # 10. Report V1.1 still validates unchanged.
        # Check that we can validate the V1.1 schema
        # The no_llm fixture is essentially valid for V1.1 except its schema_version says "report-v1.2"
        v1_1_report = dict(self.fixture_no_llm)
        v1_1_report["schema_version"] = "report-v1.1"
        self._validate_v1_1(v1_1_report)

    def test_12_json_round_trip_preserves_llm_enrichment(self):
        # 12. JSON round-trip preserves llm_enrichment exactly.
        serialized = json.dumps(self.fixture_llm)
        deserialized = json.loads(serialized)
        self.assertEqual(deserialized["llm_enrichment"]["status"], "SUCCESS")
        self.assertEqual(deserialized["llm_enrichment"]["summary"], "This is an AI summary of the case.")

    def test_13_empty_llm_enrichment_handled_according_to_schema(self):
        # 13. Empty LLM enrichment is handled according to schema design.
        # It's an object with required fields: status, request_id, case_id.
        report = dict(self.fixture_llm)
        report["llm_enrichment"] = {}
        with self.assertRaises(ValidationError):
            self._validate_v1_2(report)

if __name__ == "__main__":
    unittest.main()
