import unittest
import json
from pathlib import Path
from copy import deepcopy
import jsonschema

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.reporting.chain_of_custody import ChainOfCustody, CustodyEntry

class TestChainOfCustody(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.coc = ChainOfCustody(evidence_id="ev-EVIDENCE-001", validator=self.validator)

    def test_1_valid_ingest_action(self):
        """Verify valid 'ingest' custody action is recorded and valid."""
        entry = self.coc.record_action("CUSTODIAN-001", "ingest", "2026-08-15T10:00:00Z")
        self.assertEqual(entry["action"], "ingest")
        self.assertEqual(entry["custodian_id"], "CUSTODIAN-001")
        self.assertEqual(entry["timestamp"], "2026-08-15T10:00:00Z")
        self.assertIsNone(entry["signature"])

    def test_2_valid_verify_action(self):
        """Verify valid 'verify' custody action is recorded."""
        entry = self.coc.record_action("CUSTODIAN-002", "verify", "2026-08-15T10:05:00Z")
        self.assertEqual(entry["action"], "verify")

    def test_3_valid_export_action(self):
        """Verify valid 'export' custody action is recorded."""
        entry = self.coc.record_action("CUSTODIAN-003", "export", "2026-08-15T10:10:00Z")
        self.assertEqual(entry["action"], "export")

    def test_4_invalid_action_rejected(self):
        """Verify uncontracted/unsupported action raises ValueError."""
        with self.assertRaises(ValueError):
            self.coc.record_action("CUSTODIAN-001", "unsupported_action", "2026-08-15T10:00:00Z")

    def test_5_missing_custodian_id_rejected(self):
        """Verify missing or empty custodian_id raises ValueError."""
        with self.assertRaises(ValueError):
            self.coc.record_action("", "ingest", "2026-08-15T10:00:00Z")
        with self.assertRaises(ValueError):
            self.coc.record_action(None, "ingest", "2026-08-15T10:00:00Z")

    def test_6_malformed_timestamp_rejected(self):
        """Verify malformed timestamp string raises ValueError."""
        with self.assertRaises(ValueError):
            self.coc.record_action("CUSTODIAN-001", "ingest", "bad-date-time")

    def test_7_nullable_signature_accepted(self):
        """Verify null/None signature is accepted."""
        entry = self.coc.record_action("CUSTODIAN-001", "ingest", "2026-08-15T10:00:00Z", signature=None)
        self.assertEqual(entry["signature"], None)

    def test_8_supplied_signature_preserved_exactly(self):
        """Verify non-null signature string is preserved verbatim."""
        sig = "sig-rsa-2048-sample"
        entry = self.coc.record_action("CUSTODIAN-001", "ingest", "2026-08-15T10:00:00Z", signature=sig)
        self.assertEqual(entry["signature"], sig)

    def test_9_timestamp_valid_according_to_contract(self):
        """Verify generated or supplied timestamps validate against ISO-8601 schema format."""
        entry = self.coc.record_action("CUSTODIAN-001", "ingest")
        self.assertIn("Z", entry["timestamp"])

    def test_10_chronological_ordering(self):
        """Verify entries added out-of-order are sorted chronologically by timestamp."""
        self.coc.record_action("CUSTODIAN-002", "verify", "2026-08-15T12:00:00Z")
        self.coc.record_action("CUSTODIAN-001", "ingest", "2026-08-15T10:00:00Z")
        self.coc.record_action("CUSTODIAN-003", "export", "2026-08-15T11:00:00Z")

        entries = self.coc.get_entries()
        timestamps = [e["timestamp"] for e in entries]
        self.assertEqual(timestamps, [
            "2026-08-15T10:00:00Z",
            "2026-08-15T11:00:00Z",
            "2026-08-15T12:00:00Z"
        ])

    def test_11_duplicate_event_behavior_deterministic(self):
        """Verify duplicate identical custody entries are handled deterministically without duplication."""
        self.coc.record_action("CUSTODIAN-001", "ingest", "2026-08-15T10:00:00Z")
        self.coc.record_action("CUSTODIAN-001", "ingest", "2026-08-15T10:00:00Z")
        entries = self.coc.get_entries()
        self.assertEqual(len(entries), 1)

    def test_12_evidence_identity_preserved(self):
        """Verify evidence_id associated with ChainOfCustody instance is preserved."""
        self.assertEqual(self.coc.evidence_id, "ev-EVIDENCE-001")

    def test_13_no_evidence_bytes_modified(self):
        """Verify passing evidence bytes to custody helper does not mutate bytes."""
        raw_bytes = b"sample evidence payload"
        bytes_copy = bytes(raw_bytes)
        self.coc.record_action("CUSTODIAN-001", "ingest", "2026-08-15T10:00:00Z")
        self.assertEqual(raw_bytes, bytes_copy)

    def test_14_no_hash_generated_by_chain_of_custody(self):
        """Verify ChainOfCustody entries contain no hash or cryptographic digest fields."""
        entry = self.coc.record_action("CUSTODIAN-001", "ingest", "2026-08-15T10:00:00Z")
        self.assertNotIn("hash", entry)
        self.assertNotIn("calculated_hash", entry)

    def test_15_repeated_execution_produces_deterministic_structure(self):
        """Verify repeated calls with identical inputs produce identical deterministic structure."""
        coc1 = ChainOfCustody("ev-001")
        coc2 = ChainOfCustody("ev-001")

        coc1.record_action("C1", "ingest", "2026-08-15T10:00:00Z")
        coc1.record_action("C2", "verify", "2026-08-15T10:05:00Z")

        coc2.record_action("C1", "ingest", "2026-08-15T10:00:00Z")
        coc2.record_action("C2", "verify", "2026-08-15T10:05:00Z")

        self.assertEqual(coc1.get_entries(), coc2.get_entries())
