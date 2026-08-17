import unittest
import json
from pathlib import Path
from copy import deepcopy
import jsonschema
from datetime import datetime

def is_iso8601(val):
    if not isinstance(val, str):
        return True
    try:
        dt = datetime.fromisoformat(val.replace("Z", "+00:00"))
        return dt.tzinfo is not None
    except Exception:
        return False

FORMAT_CHECKER = jsonschema.FormatChecker()
FORMAT_CHECKER.checks("date-time")(is_iso8601)

class TestEvidenceIntegrityContract(unittest.TestCase):
    def setUp(self):
        contracts_dir = Path(__file__).resolve().parent.parent.parent.parent / "docs" / "contracts"
        schema_path = contracts_dir / "evidence-integrity-v1.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            self.schema = json.load(f)

        fixture_path = (
            Path(__file__).resolve().parent.parent.parent.parent / "fixtures"
            / "evidence"
            / "evidence-integrity-v1-valid.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.valid_fixture = json.load(f)

    def test_1_valid_v1_contract(self):
        """Verify valid evidence-integrity-v1 fixture passes schema validation."""
        jsonschema.validate(
            instance=self.valid_fixture,
            schema=self.schema,
            format_checker=FORMAT_CHECKER
        )

    def test_2_invalid_schema_version(self):
        """Verify invalid schema_version is rejected by schema validation."""
        invalid_payload = deepcopy(self.valid_fixture)
        invalid_payload["schema_version"] = "invalid-schema-v2"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_payload, schema=self.schema)

    def test_3_invalid_evidence_type(self):
        """Verify invalid evidence_type is rejected by schema validation."""
        invalid_payload = deepcopy(self.valid_fixture)
        invalid_payload["evidence_type"] = "unsupported_type"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_payload, schema=self.schema)

    def test_4_invalid_hash_algorithm(self):
        """Verify invalid hash_algorithm is rejected by schema validation."""
        invalid_payload = deepcopy(self.valid_fixture)
        invalid_payload["hash_algorithm"] = "SHA-1"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_payload, schema=self.schema)

    def test_5_invalid_verification_status(self):
        """Verify invalid verification_status is rejected by schema validation."""
        invalid_payload = deepcopy(self.valid_fixture)
        invalid_payload["verification_status"] = "unknown_status"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_payload, schema=self.schema)

    def test_6_invalid_evidence_id(self):
        """Verify missing evidence_id is rejected by schema validation."""
        invalid_payload = deepcopy(self.valid_fixture)
        del invalid_payload["evidence_id"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_payload, schema=self.schema)

    def test_7_case_id_linkage(self):
        """Verify case_id linkage is mandatory and validated."""
        invalid_payload = deepcopy(self.valid_fixture)
        del invalid_payload["case_id"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_payload, schema=self.schema)

    def test_8_nullable_signature(self):
        """Verify custody entry signature can be null or string."""
        payload_null_sig = deepcopy(self.valid_fixture)
        payload_null_sig["chain_of_custody"][0]["signature"] = None
        jsonschema.validate(instance=payload_null_sig, schema=self.schema, format_checker=FORMAT_CHECKER)

        payload_str_sig = deepcopy(self.valid_fixture)
        payload_str_sig["chain_of_custody"][0]["signature"] = "sig-sample-123"
        jsonschema.validate(instance=payload_str_sig, schema=self.schema, format_checker=FORMAT_CHECKER)

    def test_9_additional_properties_rejected(self):
        """Verify uncontracted extra property at root is rejected."""
        invalid_payload = deepcopy(self.valid_fixture)
        invalid_payload["uncontracted_extra_field"] = "bad"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid_payload, schema=self.schema)

    def test_10_deterministic_serialization(self):
        """Verify repeated serialization and validation yields identical deterministic output."""
        ser1 = json.dumps(self.valid_fixture, sort_keys=True)
        ser2 = json.dumps(self.valid_fixture, sort_keys=True)
        self.assertEqual(ser1, ser2)
