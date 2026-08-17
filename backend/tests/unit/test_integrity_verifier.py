import unittest
import hashlib
from datetime import datetime, timezone
import jsonschema

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.reporting.integrity_verifier import IntegrityVerifier

class TestIntegrityVerifier(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.verifier = IntegrityVerifier(self.validator)

        self.sample_bytes = b"hello world"
        self.sha256_hash = hashlib.sha256(self.sample_bytes).hexdigest()
        self.sha512_hash = hashlib.sha512(self.sample_bytes).hexdigest()
        self.md5_hash = hashlib.md5(self.sample_bytes).hexdigest()

        self.base_metadata = {
            "evidence_id": "ev-TEST-001",
            "case_id": "CASE-TEST-001",
            "evidence_type": "pcap",
            "source_id": "SRC-001",
            "expected_hash": self.sha256_hash,
            "hash_algorithm": "SHA-256"
        }

    def test_1_valid_matching_sha256(self):
        """Verify matching SHA-256 hash yields status 'verified'."""
        result = self.verifier.verify(self.base_metadata, self.sample_bytes)
        self.assertEqual(result["verification_status"], "verified")
        self.assertEqual(result["calculated_hash"], self.sha256_hash)
        self.assertIsNotNone(result["verified_at"])

    def test_2_valid_matching_sha512(self):
        """Verify matching SHA-512 hash yields status 'verified'."""
        meta = dict(self.base_metadata, expected_hash=self.sha512_hash, hash_algorithm="SHA-512")
        result = self.verifier.verify(meta, self.sample_bytes)
        self.assertEqual(result["verification_status"], "verified")
        self.assertEqual(result["calculated_hash"], self.sha512_hash)

    def test_3_valid_matching_md5(self):
        """Verify matching MD5 hash yields status 'verified'."""
        meta = dict(self.base_metadata, expected_hash=self.md5_hash, hash_algorithm="MD5")
        result = self.verifier.verify(meta, self.sample_bytes)
        self.assertEqual(result["verification_status"], "verified")
        self.assertEqual(result["calculated_hash"], self.md5_hash)

    def test_4_hash_mismatch(self):
        """Verify differing expected hash yields status 'mismatch'."""
        meta = dict(self.base_metadata, expected_hash="0000000000000000000000000000000000000000000000000000000000000000")
        result = self.verifier.verify(meta, self.sample_bytes)
        self.assertEqual(result["verification_status"], "mismatch")

    def test_5_missing_expected_hash(self):
        """Verify missing expected_hash yields status 'unverified'."""
        meta = dict(self.base_metadata, expected_hash=None)
        result = self.verifier.verify(meta, self.sample_bytes)
        self.assertEqual(result["verification_status"], "unverified")

    def test_6_missing_hash_algorithm(self):
        """Verify missing hash_algorithm yields status 'unverified' without defaulting."""
        meta = dict(self.base_metadata, hash_algorithm=None)
        result = self.verifier.verify(meta, self.sample_bytes)
        self.assertEqual(result["verification_status"], "unverified")
        self.assertIsNone(result["calculated_hash"])

    def test_7_unsupported_hash_algorithm(self):
        """Verify unsupported hash_algorithm yields status 'unverified' without guessing."""
        meta = dict(self.base_metadata, hash_algorithm="SHA-1")
        result = self.verifier.verify(meta, self.sample_bytes)
        self.assertEqual(result["verification_status"], "unverified")
        self.assertIsNone(result["calculated_hash"])

    def test_8_empty_evidence_bytes(self):
        """Verify empty bytes b'' calculates digest correctly and verifies matching expected hash."""
        empty_bytes = b""
        empty_hash = hashlib.sha256(empty_bytes).hexdigest()
        meta = dict(self.base_metadata, expected_hash=empty_hash)
        result = self.verifier.verify(meta, empty_bytes)
        self.assertEqual(result["verification_status"], "verified")
        self.assertEqual(result["calculated_hash"], empty_hash)

    def test_9_exact_evidence_id_preservation(self):
        """Verify evidence_id is preserved verbatim."""
        result = self.verifier.verify(self.base_metadata, self.sample_bytes)
        self.assertEqual(result["evidence_id"], "ev-TEST-001")

    def test_10_exact_case_id_preservation(self):
        """Verify case_id is preserved verbatim."""
        result = self.verifier.verify(self.base_metadata, self.sample_bytes)
        self.assertEqual(result["case_id"], "CASE-TEST-001")

    def test_11_exact_evidence_type_preservation(self):
        """Verify evidence_type is preserved verbatim."""
        result = self.verifier.verify(self.base_metadata, self.sample_bytes)
        self.assertEqual(result["evidence_type"], "pcap")

    def test_12_exact_source_id_preservation(self):
        """Verify source_id is preserved verbatim."""
        result = self.verifier.verify(self.base_metadata, self.sample_bytes)
        self.assertEqual(result["source_id"], "SRC-001")

    def test_13_verified_at_exists_after_verification(self):
        """Verify verified_at timestamp is generated upon verification execution."""
        before = datetime.now(timezone.utc)
        result = self.verifier.verify(self.base_metadata, self.sample_bytes)
        after = datetime.now(timezone.utc)

        self.assertIsNotNone(result["verified_at"])
        ts = datetime.fromisoformat(result["verified_at"].replace("Z", "+00:00"))
        self.assertTrue(before <= ts <= after)

    def test_14_deterministic_calculated_hash(self):
        """Verify repeated calculation produces identical hash across runs."""
        r1 = self.verifier.verify(self.base_metadata, self.sample_bytes)
        r2 = self.verifier.verify(self.base_metadata, self.sample_bytes)
        self.assertEqual(r1["calculated_hash"], r2["calculated_hash"])

    def test_15_tampered_not_automatically_generated(self):
        """Verify hash mismatch produces 'mismatch', NEVER 'tampered'."""
        meta = dict(self.base_metadata, expected_hash="ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")
        result = self.verifier.verify(meta, self.sample_bytes)
        self.assertNotEqual(result["verification_status"], "tampered")
        self.assertEqual(result["verification_status"], "mismatch")

    def test_16_malformed_metadata_rejected(self):
        """Verify metadata missing mandatory evidence_id or case_id raises ValueError."""
        bad_meta = dict(self.base_metadata)
        del bad_meta["evidence_id"]
        with self.assertRaises(ValueError):
            self.verifier.verify(bad_meta, self.sample_bytes)

    def test_17_original_evidence_bytes_not_modified(self):
        """Verify evidence_bytes content is not modified by verifier."""
        bytes_copy = bytes(self.sample_bytes)
        self.verifier.verify(self.base_metadata, self.sample_bytes)
        self.assertEqual(self.sample_bytes, bytes_copy)
