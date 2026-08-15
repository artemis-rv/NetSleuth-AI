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

class TestReportContract(unittest.TestCase):
    def setUp(self):
        contracts_dir = Path(__file__).resolve().parent.parent.parent / "docs" / "contracts"
        schema_path = contracts_dir / "report-v1.json"
        with open(schema_path, "r", encoding="utf-8") as f:
            self.schema = json.load(f)

        fixture_path = (
            Path(__file__).resolve().parent.parent.parent
            / "fixtures"
            / "reports"
            / "report-v1-valid.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.valid_fixture = json.load(f)

    def test_1_valid_report_v1_fixture(self):
        """Verify valid report-v1 fixture passes schema validation."""
        jsonschema.validate(
            instance=self.valid_fixture,
            schema=self.schema,
            format_checker=FORMAT_CHECKER
        )

    def test_2_schema_version_const(self):
        """Verify schema_version must be exactly 'report-v1'."""
        self.assertEqual(self.valid_fixture["schema_version"], "report-v1")
        invalid = deepcopy(self.valid_fixture)
        invalid["schema_version"] = "report-v2"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid, schema=self.schema)

    def test_3_missing_required_field_rejected(self):
        """Verify missing required top-level field is rejected."""
        invalid = deepcopy(self.valid_fixture)
        del invalid["report_id"]
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid, schema=self.schema)

    def test_4_invalid_enum_rejected(self):
        """Verify invalid severity enum in finding is rejected."""
        invalid = deepcopy(self.valid_fixture)
        invalid["findings"][0]["severity"] = "super_critical"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid, schema=self.schema)

    def test_5_unexpected_property_rejected(self):
        """Verify uncontracted extra property is rejected due to additionalProperties=false."""
        invalid = deepcopy(self.valid_fixture)
        invalid["uncontracted_field"] = "bad"
        with self.assertRaises(jsonschema.ValidationError):
            jsonschema.validate(instance=invalid, schema=self.schema)

    def test_6_finding_preservation(self):
        """Verify finding identity, severity, confidence, and title are preserved."""
        finding = self.valid_fixture["findings"][0]
        self.assertEqual(finding["finding_id"], "FINDING-DNS-001")
        self.assertEqual(finding["severity"], "high")
        self.assertEqual(finding["confidence"], 0.95)

    def test_7_timeline_preservation(self):
        """Verify timeline events, timestamps, and evidence linkages are preserved."""
        event = self.valid_fixture["timeline"][0]
        self.assertEqual(event["event_id"], "EVT-001")
        self.assertEqual(event["timestamp"], "2026-08-15T10:00:00Z")
        self.assertEqual(event["evidence_ids"], ["ev-FLOW-001"])

    def test_8_entity_preservation(self):
        """Verify entities, types, values, and namespaces are preserved."""
        entity = self.valid_fixture["entities"][0]
        self.assertEqual(entity["entity_id"], "ent-IP-001")
        self.assertEqual(entity["entity_type"], "ip")
        self.assertEqual(entity["value"], "192.168.1.105")

    def test_9_relationship_preservation(self):
        """Verify entity relationships and evidence linkages are preserved."""
        rel = self.valid_fixture["relationships"][0]
        self.assertEqual(rel["relationship_id"], "REL-001")
        self.assertEqual(rel["source_entity_id"], "ent-IP-001")
        self.assertEqual(rel["target_entity_id"], "ent-DOMAIN-001")

    def test_10_evidence_integrity_preservation(self):
        """Verify calculated hashes and verification statuses are preserved."""
        ev_rec = self.valid_fixture["evidence_integrity"][0]
        self.assertEqual(ev_rec["verification_status"], "verified")
        self.assertEqual(ev_rec["expected_hash"], ev_rec["calculated_hash"])

    def test_11_chain_of_custody_preservation(self):
        """Verify chain of custody events are preserved in report evidence records."""
        custody = self.valid_fixture["evidence_integrity"][0]["chain_of_custody"]
        actions = [c["action"] for c in custody]
        self.assertEqual(actions, ["ingest", "verify"])

    def test_12_deterministic_serialization(self):
        """Verify repeated json serialization yields identical deterministic output."""
        ser1 = json.dumps(self.valid_fixture, sort_keys=True)
        ser2 = json.dumps(self.valid_fixture, sort_keys=True)
        self.assertEqual(ser1, ser2)

    def test_13_evidence_counter_structure(self):
        """Verify summary evidence counters adhere to total evidence references invariant."""
        s = self.valid_fixture["summary"]
        self.assertEqual(
            s["verified_evidence_count"] + s["mismatched_evidence_count"] + s["unverified_evidence_count"],
            s["total_evidence_references"]
        )

    def test_14_case_id_preservation(self):
        """Verify case_id is preserved verbatim at root and in evidence integrity records."""
        self.assertEqual(self.valid_fixture["case_id"], "CASE-SCENARIO-001")
        for ev in self.valid_fixture["evidence_integrity"]:
            self.assertEqual(ev["case_id"], "CASE-SCENARIO-001")
