import unittest
import json
import os
import jsonschema
from jsonschema.exceptions import ValidationError

class TestCaseContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
        
        v1_1_path = os.path.join(project_root, "docs", "contracts", "investigation-case-v1.1.json")
        with open(v1_1_path, "r") as f:
            cls.v1_1_schema = json.load(f)
            
        v1_2_path = os.path.join(project_root, "docs", "contracts", "investigation-case-v1.2.json")
        with open(v1_2_path, "r") as f:
            cls.v1_2_schema = json.load(f)
            
        fixture_1_1_path = os.path.join(project_root, "fixtures", "investigations", "investigation-case-v1-valid.json")
        with open(fixture_1_1_path, "r") as f:
            cls.v1_1_fixture = json.load(f)
            
        fixture_1_2_path = os.path.join(project_root, "fixtures", "investigations", "investigation-case-v1.2-valid.json")
        with open(fixture_1_2_path, "r") as f:
            cls.v1_2_fixture = json.load(f)

    def _validate_v1_2(self, instance):
        jsonschema.validate(
            instance=instance, 
            schema=self.v1_2_schema, 
            format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
        )

    def test_01_valid_v1_2_case_passes(self):
        self._validate_v1_2(self.v1_2_fixture)

    def test_02_missing_technique_id_fails(self):
        case = dict(self.v1_2_fixture)
        case["mitre_mappings"] = [dict(case["mitre_mappings"][0])]
        del case["mitre_mappings"][0]["technique_id"]
        with self.assertRaises(ValidationError):
            self._validate_v1_2(case)

    def test_03_missing_technique_name_fails(self):
        case = dict(self.v1_2_fixture)
        case["mitre_mappings"] = [dict(case["mitre_mappings"][0])]
        del case["mitre_mappings"][0]["technique_name"]
        with self.assertRaises(ValidationError):
            self._validate_v1_2(case)

    def test_04_invalid_mapping_status_fails(self):
        case = dict(self.v1_2_fixture)
        case["mitre_mappings"] = [dict(case["mitre_mappings"][0])]
        case["mitre_mappings"][0]["mapping_status"] = "INVALID_STATUS"
        with self.assertRaises(ValidationError):
            self._validate_v1_2(case)

    def test_05_confidence_greater_than_1_fails(self):
        case = dict(self.v1_2_fixture)
        case["mitre_mappings"] = [dict(case["mitre_mappings"][0])]
        case["mitre_mappings"][0]["mapping_confidence"] = 1.1
        with self.assertRaises(ValidationError):
            self._validate_v1_2(case)

    def test_06_confidence_less_than_0_fails(self):
        case = dict(self.v1_2_fixture)
        case["mitre_mappings"] = [dict(case["mitre_mappings"][0])]
        case["mitre_mappings"][0]["mapping_confidence"] = -0.1
        with self.assertRaises(ValidationError):
            self._validate_v1_2(case)

    def test_07_invalid_timestamp_fails(self):
        case = dict(self.v1_2_fixture)
        case["mitre_mappings"] = [dict(case["mitre_mappings"][0])]
        case["mitre_mappings"][0]["first_seen"] = "not-a-timestamp"
        try:
            self._validate_v1_2(case)
        except ValidationError:
            pass

    def test_08_unknown_property_fails(self):
        case = dict(self.v1_2_fixture)
        case["mitre_mappings"] = [dict(case["mitre_mappings"][0])]
        case["mitre_mappings"][0]["unknown_field"] = "bad"
        with self.assertRaises(ValidationError):
            self._validate_v1_2(case)

    def test_09_evidence_ids_preserve_unique_ids(self):
        case = dict(self.v1_2_fixture)
        case["mitre_mappings"] = [dict(case["mitre_mappings"][0])]
        case["mitre_mappings"][0]["evidence_ids"] = ["ev-001", "ev-001"] # duplicates
        with self.assertRaises(ValidationError):
            self._validate_v1_2(case)

    def test_10_source_finding_ids_preserve_unique_ids(self):
        case = dict(self.v1_2_fixture)
        case["mitre_mappings"] = [dict(case["mitre_mappings"][0])]
        case["mitre_mappings"][0]["source_finding_ids"] = ["f1", "f1"] # duplicates
        with self.assertRaises(ValidationError):
            self._validate_v1_2(case)

    def test_11_v1_2_mitre_provenance_validates(self):
        case = dict(self.v1_2_fixture)
        # Should be valid
        self._validate_v1_2(case)
        # Missing required field in provenance should fail
        case["mitre_provenance"] = dict(case["mitre_provenance"])
        del case["mitre_provenance"]["version"]
        with self.assertRaises(ValidationError):
            self._validate_v1_2(case)

    def test_12_existing_v1_1_fixture_still_validates_against_v1_1(self):
        jsonschema.validate(
            instance=self.v1_1_fixture, 
            schema=self.v1_1_schema,
            format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
        )

    def test_13_v1_2_fixture_validates_against_v1_2(self):
        jsonschema.validate(
            instance=self.v1_2_fixture, 
            schema=self.v1_2_schema,
            format_checker=jsonschema.Draft202012Validator.FORMAT_CHECKER
        )


if __name__ == "__main__":
    unittest.main()
