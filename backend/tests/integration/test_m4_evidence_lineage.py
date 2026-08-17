import unittest
import json
import hashlib
from pathlib import Path
from copy import deepcopy

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.reporting.evidence_package import M4EvidencePackageBuilder, M4EvidencePackage

class TestM4EvidenceLineage(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.builder = M4EvidencePackageBuilder(self.validator)

        fixture_path = (
            Path(__file__).resolve().parent.parent.parent.parent / "fixtures"
            / "investigations"
            / "investigation-case-v1-scenario-001-expected.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.scenario_001_case = json.load(f)

        self.sample_bytes = b"SCENARIO-001-PCAP-BYTES-LINEAGE-TEST"
        self.sha256_hash = hashlib.sha256(self.sample_bytes).hexdigest()

    def test_1_scenario_001_complete_lineage(self):
        """Verify complete end-to-end evidence lineage trace for Scenario 001."""
        case = deepcopy(self.scenario_001_case)
        ev_refs = case["evidence_references"]
        self.assertGreater(len(ev_refs), 0)

        # Set hash on first reference
        ev_id = ev_refs[0]["evidence_id"]
        ev_refs[0]["hash"] = self.sha256_hash
        ev_refs[0]["hash_algorithm"] = "SHA-256"

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record = pkg.get_evidence_record(ev_id)

        # Verify exact field preservation
        self.assertEqual(record["evidence_id"], ev_id)
        self.assertEqual(record["evidence_type"], ev_refs[0]["evidence_type"])
        self.assertEqual(record["source_id"], ev_refs[0]["source_id"])
        self.assertEqual(record["expected_hash"], self.sha256_hash)
        self.assertEqual(record["calculated_hash"], self.sha256_hash)
        self.assertEqual(record["verification_status"], "verified")

    def test_2_matching_hash(self):
        """Verify matching expected hash produces verification_status 'verified'."""
        case = deepcopy(self.scenario_001_case)
        ev_id = case["evidence_references"][0]["evidence_id"]
        case["evidence_references"][0]["hash"] = self.sha256_hash
        case["evidence_references"][0]["hash_algorithm"] = "SHA-256"

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record = pkg.get_evidence_record(ev_id)
        self.assertEqual(record["verification_status"], "verified")
        self.assertEqual(record["calculated_hash"], self.sha256_hash)

    def test_3_mismatching_hash(self):
        """Verify mismatching expected hash produces 'mismatch', NEVER 'tampered'."""
        case = deepcopy(self.scenario_001_case)
        ev_id = case["evidence_references"][0]["evidence_id"]
        case["evidence_references"][0]["hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        case["evidence_references"][0]["hash_algorithm"] = "SHA-256"

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record = pkg.get_evidence_record(ev_id)
        self.assertEqual(record["verification_status"], "mismatch")
        self.assertNotEqual(record["verification_status"], "tampered")

    def test_4_unavailable_evidence(self):
        """Verify missing evidence bytes leaves status as 'unverified'."""
        pkg = self.builder.build(self.scenario_001_case)
        for record in pkg.get_all_evidence_records():
            self.assertEqual(record["verification_status"], "unverified")

    def test_5_missing_algorithm(self):
        """Verify missing hash algorithm leaves status as 'unverified' without defaulting."""
        case = deepcopy(self.scenario_001_case)
        ev_id = case["evidence_references"][0]["evidence_id"]
        case["evidence_references"][0]["hash_algorithm"] = None

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record = pkg.get_evidence_record(ev_id)
        self.assertEqual(record["verification_status"], "unverified")

    def test_6_undeclared_evidence(self):
        """Verify timeline referencing undeclared evidence ID raises ValueError."""
        case = deepcopy(self.scenario_001_case)
        case["timeline"][0]["evidence_ids"].append("ev-UNDECLARED-ERR")

        with self.assertRaises(ValueError):
            self.builder.build(case)

    def test_7_altered_evidence_id(self):
        """Verify altering evidence ID on reference creates referential integrity failure."""
        case = deepcopy(self.scenario_001_case)
        case["evidence_references"][0]["evidence_id"] = "ev-ALTERED-ID"

        with self.assertRaises(ValueError):
            self.builder.build(case)

    def test_8_altered_source_id(self):
        """Verify duplicate evidence reference with conflicting source_id raises ValueError."""
        case = deepcopy(self.scenario_001_case)
        dup = deepcopy(case["evidence_references"][0])
        dup["source_id"] = "SRC-ALTERED-CONFLICT"
        case["evidence_references"].append(dup)

        with self.assertRaises(ValueError):
            self.builder.build(case)

    def test_9_altered_evidence_type(self):
        """Verify duplicate evidence reference with conflicting evidence_type raises ValueError."""
        case = deepcopy(self.scenario_001_case)
        dup = deepcopy(case["evidence_references"][0])
        dup["evidence_type"] = "dns"
        case["evidence_references"].append(dup)

        with self.assertRaises(ValueError):
            self.builder.build(case)

    def test_10_duplicate_conflict(self):
        """Verify duplicate evidence reference with conflicting expected hash raises ValueError."""
        case = deepcopy(self.scenario_001_case)
        dup = deepcopy(case["evidence_references"][0])
        dup["hash"] = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
        case["evidence_references"].append(dup)

        with self.assertRaises(ValueError):
            self.builder.build(case)

    def test_11_custody_lineage(self):
        """Verify custody actions ingest -> verify -> export form an ordered lineage."""
        case = deepcopy(self.scenario_001_case)
        ev_id = case["evidence_references"][0]["evidence_id"]
        case["evidence_references"][0]["hash"] = self.sha256_hash
        case["evidence_references"][0]["hash_algorithm"] = "SHA-256"

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        pkg.export_evidence(ev_id)

        record = pkg.get_evidence_record(ev_id)
        custody_actions = [c["action"] for c in record["chain_of_custody"]]
        self.assertEqual(custody_actions, ["ingest", "verify", "export"])

    def test_12_no_fabricated_signature(self):
        """Verify signature remains null/None throughout custody lineage."""
        case = deepcopy(self.scenario_001_case)
        ev_id = case["evidence_references"][0]["evidence_id"]
        case["evidence_references"][0]["hash"] = self.sha256_hash
        case["evidence_references"][0]["hash_algorithm"] = "SHA-256"

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record = pkg.get_evidence_record(ev_id)

        for custody in record["chain_of_custody"]:
            self.assertIsNone(custody["signature"])

    def test_13_no_false_tampered_status(self):
        """Verify status never automatically becomes 'tampered'."""
        case = deepcopy(self.scenario_001_case)
        ev_id = case["evidence_references"][0]["evidence_id"]
        case["evidence_references"][0]["hash"] = "badhash"
        case["evidence_references"][0]["hash_algorithm"] = "SHA-256"

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record = pkg.get_evidence_record(ev_id)
        self.assertNotEqual(record["verification_status"], "tampered")

    def test_14_input_immutability(self):
        """Verify M3 case input payload and raw evidence bytes are not mutated."""
        case_copy = deepcopy(self.scenario_001_case)
        bytes_copy = bytes(self.sample_bytes)

        ev_id = self.scenario_001_case["evidence_references"][0]["evidence_id"]
        self.builder.build(self.scenario_001_case, evidence_payloads={ev_id: self.sample_bytes})

        self.assertEqual(self.scenario_001_case, case_copy)
        self.assertEqual(self.sample_bytes, bytes_copy)

    def test_15_deterministic_output(self):
        """Verify repeated lineage processing yields identical evidence records."""
        p1 = self.builder.build(self.scenario_001_case)
        p2 = self.builder.build(self.scenario_001_case)

        records1 = p1.get_all_evidence_records()
        records2 = p2.get_all_evidence_records()

        self.assertEqual(len(records1), len(records2))
        for r1, r2 in zip(records1, records2):
            self.assertEqual(r1["evidence_id"], r2["evidence_id"])
            self.assertEqual(r1["verification_status"], r2["verification_status"])
