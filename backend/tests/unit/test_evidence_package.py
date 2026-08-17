import unittest
import hashlib
import json
from pathlib import Path
from copy import deepcopy
import jsonschema

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.reporting.evidence_package import M4EvidencePackageBuilder, M4EvidencePackage

class TestEvidencePackage(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.builder = M4EvidencePackageBuilder(self.validator)

        fixture_path = (
            Path(__file__).resolve().parent.parent.parent.parent / "fixtures"
            / "investigations"
            / "investigation-case-v1-scenario-001-expected.json"
        )
        with open(fixture_path, "r", encoding="utf-8") as f:
            self.sample_case = json.load(f)

        self.sample_bytes = b"sample pcap payload bytes"
        self.sample_hash = hashlib.sha256(self.sample_bytes).hexdigest()

    def test_1_valid_m3_case_produces_valid_m4_package(self):
        """Verify valid M3 case builds valid M4 package."""
        pkg = self.builder.build(self.sample_case)
        self.assertIsInstance(pkg, M4EvidencePackage)
        records = pkg.get_all_evidence_records()
        self.assertGreater(len(records), 0)

    def test_2_evidence_ids_preserved_exactly(self):
        """Verify evidence IDs are preserved verbatim."""
        pkg = self.builder.build(self.sample_case)
        orig_ids = {e["evidence_id"] for e in self.sample_case["evidence_references"]}
        pkg_ids = {r["evidence_id"] for r in pkg.get_all_evidence_records()}
        self.assertEqual(orig_ids, pkg_ids)

    def test_3_evidence_types_preserved_exactly(self):
        """Verify evidence types are preserved verbatim."""
        pkg = self.builder.build(self.sample_case)
        orig_types = {e["evidence_id"]: e["evidence_type"] for e in self.sample_case["evidence_references"]}
        for record in pkg.get_all_evidence_records():
            self.assertEqual(record["evidence_type"], orig_types[record["evidence_id"]])

    def test_4_source_id_preserved_exactly(self):
        """Verify source_id is preserved verbatim."""
        pkg = self.builder.build(self.sample_case)
        orig_sources = {e["evidence_id"]: e.get("source_id") for e in self.sample_case["evidence_references"]}
        for record in pkg.get_all_evidence_records():
            self.assertEqual(record.get("source_id"), orig_sources[record["evidence_id"]])

    def test_5_expected_hash_preserved_exactly(self):
        """Verify expected hash is preserved verbatim."""
        pkg = self.builder.build(self.sample_case)
        orig_hashes = {e["evidence_id"]: e.get("hash") for e in self.sample_case["evidence_references"]}
        for record in pkg.get_all_evidence_records():
            self.assertEqual(record.get("expected_hash"), orig_hashes[record["evidence_id"]])

    def test_6_hash_algorithm_preserved_exactly(self):
        """Verify hash algorithm is preserved verbatim."""
        pkg = self.builder.build(self.sample_case)
        orig_algos = {e["evidence_id"]: e.get("hash_algorithm") for e in self.sample_case["evidence_references"]}
        for record in pkg.get_all_evidence_records():
            self.assertEqual(record.get("hash_algorithm"), orig_algos[record["evidence_id"]])

    def test_7_actual_evidence_bytes_cause_verifier_to_execute(self):
        """Verify supplying evidence bytes triggers IntegrityVerifier execution."""
        case = deepcopy(self.sample_case)
        case["evidence_references"][0]["hash"] = self.sample_hash
        case["evidence_references"][0]["hash_algorithm"] = "SHA-256"
        ev_id = case["evidence_references"][0]["evidence_id"]

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record = pkg.get_evidence_record(ev_id)
        self.assertEqual(record["calculated_hash"], self.sample_hash)

    def test_8_matching_hash_produces_verified(self):
        """Verify matching hash yields 'verified' status."""
        case = deepcopy(self.sample_case)
        case["evidence_references"][0]["hash"] = self.sample_hash
        case["evidence_references"][0]["hash_algorithm"] = "SHA-256"
        ev_id = case["evidence_references"][0]["evidence_id"]

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record = pkg.get_evidence_record(ev_id)
        self.assertEqual(record["verification_status"], "verified")

    def test_9_mismatching_hash_produces_mismatch(self):
        """Verify mismatching hash yields 'mismatch' status."""
        case = deepcopy(self.sample_case)
        case["evidence_references"][0]["hash"] = "0000000000000000000000000000000000000000000000000000000000000000"
        case["evidence_references"][0]["hash_algorithm"] = "SHA-256"
        ev_id = case["evidence_references"][0]["evidence_id"]

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record = pkg.get_evidence_record(ev_id)
        self.assertEqual(record["verification_status"], "mismatch")

    def test_10_missing_evidence_bytes_does_not_produce_verified(self):
        """Verify missing evidence bytes leaves status as 'unverified'."""
        pkg = self.builder.build(self.sample_case)
        record = pkg.get_all_evidence_records()[0]
        self.assertEqual(record["verification_status"], "unverified")
        self.assertNotIn("calculated_hash", record)

    def test_11_missing_hash_algorithm_does_not_default_to_sha256(self):
        """Verify missing hash algorithm leaves status as 'unverified' without defaulting."""
        case = deepcopy(self.sample_case)
        case["evidence_references"][0]["hash_algorithm"] = None
        ev_id = case["evidence_references"][0]["evidence_id"]

        pkg = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record = pkg.get_evidence_record(ev_id)
        self.assertEqual(record["verification_status"], "unverified")
        self.assertNotIn("calculated_hash", record)

    def test_12_chain_of_custody_ingest_entry_created(self):
        """Verify ingest custody entry is automatically created for all evidence items."""
        pkg = self.builder.build(self.sample_case)
        for record in pkg.get_all_evidence_records():
            custody = record["chain_of_custody"]
            actions = [c["action"] for c in custody]
            self.assertIn("ingest", actions)

    def test_13_verify_custody_entry_exists_only_after_actual_verification(self):
        """Verify 'verify' custody action is recorded only when evidence bytes are verified."""
        case = deepcopy(self.sample_case)
        case["evidence_references"][0]["hash"] = self.sample_hash
        case["evidence_references"][0]["hash_algorithm"] = "SHA-256"
        ev_id = case["evidence_references"][0]["evidence_id"]

        pkg_no_verify = self.builder.build(case)
        record_no_ver = pkg_no_verify.get_evidence_record(ev_id)
        actions_no_ver = [c["action"] for c in record_no_ver.get("chain_of_custody", [])]
        self.assertNotIn("verify", actions_no_ver)

        pkg_verified = self.builder.build(case, evidence_payloads={ev_id: self.sample_bytes})
        record_ver = pkg_verified.get_evidence_record(ev_id)
        actions_ver = [c["action"] for c in record_ver["chain_of_custody"]]
        self.assertIn("verify", actions_ver)

    def test_14_evidence_export_creates_export_custody_entry(self):
        """Verify export_evidence records export custody action."""
        pkg = self.builder.build(self.sample_case)
        ev_id = self.sample_case["evidence_references"][0]["evidence_id"]
        pkg.export_evidence(ev_id, custodian_id="exporter-001")

        record = pkg.get_evidence_record(ev_id)
        actions = [c["action"] for c in record["chain_of_custody"]]
        self.assertIn("export", actions)

    def test_15_duplicate_evidence_ids_deterministic(self):
        """Verify duplicate evidence IDs with identical metadata are deduplicated deterministically."""
        case = deepcopy(self.sample_case)
        case["evidence_references"].append(deepcopy(case["evidence_references"][0]))
        pkg = self.builder.build(case)
        self.assertEqual(len(pkg.get_all_evidence_records()), len(self.sample_case["evidence_references"]))

    def test_16_conflicting_duplicate_evidence_metadata_rejected(self):
        """Verify duplicate evidence IDs with conflicting metadata raise ValueError."""
        case = deepcopy(self.sample_case)
        dup = deepcopy(case["evidence_references"][0])
        dup["evidence_type"] = "dns"  # Conflict
        case["evidence_references"].append(dup)

        with self.assertRaises(ValueError):
            self.builder.build(case)

    def test_17_undeclared_evidence_references_rejected(self):
        """Verify timeline events referencing undeclared evidence IDs raise ValueError."""
        case = deepcopy(self.sample_case)
        case["timeline"][0]["evidence_ids"].append("ev-UNDECLARED-999")

        with self.assertRaises(ValueError):
            self.builder.build(case)

    def test_18_no_evidence_invented(self):
        """Verify package contains only evidence IDs present in input case."""
        pkg = self.builder.build(self.sample_case)
        orig_ids = {e["evidence_id"] for e in self.sample_case["evidence_references"]}
        pkg_ids = {r["evidence_id"] for r in pkg.get_all_evidence_records()}
        self.assertEqual(pkg_ids.difference(orig_ids), set())

    def test_19_no_timestamps_fabricated(self):
        """Verify verified_at is None if verification did not execute."""
        pkg = self.builder.build(self.sample_case)
        for record in pkg.get_all_evidence_records():
            self.assertNotIn("verified_at", record)

    def test_20_final_package_validates_against_schema(self):
        """Verify all evidence records in final package pass contract schema validation."""
        pkg = self.builder.build(self.sample_case)
        for record in pkg.get_all_evidence_records():
            self.validator.validate("evidence-integrity-v1.json", record)

    def test_21_repeated_execution_is_deterministic(self):
        """Verify repeated build calls on identical input produce identical evidence records."""
        p1 = self.builder.build(self.sample_case)
        p2 = self.builder.build(self.sample_case)

        # Ignore variable timestamp values in custody comparison
        rec1 = p1.get_all_evidence_records()
        rec2 = p2.get_all_evidence_records()
        self.assertEqual(len(rec1), len(rec2))
        for r1, r2 in zip(rec1, rec2):
            self.assertEqual(r1["evidence_id"], r2["evidence_id"])
            self.assertEqual(r1["evidence_type"], r2["evidence_type"])

    def test_22_original_m3_input_not_mutated(self):
        """Verify original input dictionary is not modified by builder."""
        input_copy = deepcopy(self.sample_case)
        self.builder.build(self.sample_case)
        self.assertEqual(self.sample_case, input_copy)
