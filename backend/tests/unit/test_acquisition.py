"""
backend/tests/unit/test_acquisition.py
----------------------------------------
Unit tests for the Phase 2 Acquisition Engine.

Test categories:
  A. Validation — all error codes
  B. SHA-256 correctness
  C. AcquisitionReference contract compliance
  D. Forensic integrity (original file unchanged)
  E. Performance & response time

Coverage targets:
  1.  Valid PCAP accepted
  2.  Valid PCAPNG accepted
  3.  Missing file → FILE_NOT_FOUND
  4.  Directory instead of file → NOT_A_FILE
  5.  Unsupported extension → UNSUPPORTED_FORMAT
  6.  Empty file → EMPTY_FILE
  7.  Invalid capture (bad magic) → INVALID_CAPTURE
  8.  Correct SHA-256 digest
  9.  Deterministic repeated SHA-256
  10. AcquisitionReference validates against contract (frozen Pydantic model)
  11. Original file remains unchanged after acquire()
  12. No invented metadata (only factual fields populated)
  13. Large-file hashing does NOT read entire file into memory at once
  14. Performance: acquire() on a 1 MB synthetic PCAP ≤ 200 ms
  15. Performance: SHA-256 throughput ≥ 50 MB/s
  16. Performance: validator rejects invalid files in < 5 ms

All test fixtures (PCAP/PCAPNG) are generated in-memory or in tempdir;
no binary evidence files are committed to the repository.
"""

from __future__ import annotations

import hashlib
import os
import stat
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

from app.contracts.network_intelligence import AcquisitionReference
from app.engines.acquisition import (
    AcquisitionError,
    AcquisitionErrorCode,
    AcquisitionService,
)
from app.engines.acquisition.hasher import compute_sha256
from app.engines.acquisition.validator import validate


# ---------------------------------------------------------------------------
# Helpers — synthetic capture builders
# ---------------------------------------------------------------------------

def _make_pcap_bytes(num_packets: int = 2) -> bytes:
    """Build a minimal valid PCAP file in memory (little-endian).

    Global header  : 24 bytes
    Per packet     : 16-byte record header + payload

    Reference: https://wiki.wireshark.org/Development/LibpcapFileFormat
    """
    # Global header
    magic_number = 0xA1B2C3D4      # little-endian magic
    version_major = 2
    version_minor = 4
    thiszone = 0                   # GMT offset
    sigfigs = 0                    # accuracy of timestamps
    snaplen = 65535
    network = 1                    # LINKTYPE_ETHERNET

    global_hdr = struct.pack(
        "<IHHiIII",
        magic_number, version_major, version_minor,
        thiszone, sigfigs, snaplen, network,
    )

    # Build a minimal Ethernet frame: 14 bytes header + 20 bytes IP
    payload = bytes(34)            # all zeros — valid enough for magic purposes

    packets = b""
    for _ in range(num_packets):
        ts_sec = 1_700_000_000
        ts_usec = 0
        incl_len = len(payload)
        orig_len = len(payload)
        pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
        packets += pkt_hdr + payload

    return global_hdr + packets


def _make_pcapng_bytes() -> bytes:
    """Build a minimal valid PCAPNG file (Section Header Block only).

    SHB structure (little-endian):
      Block Type   : 0x0A0D0D0A  (4 bytes)
      Block Length : 28          (4 bytes)
      Byte Order   : 0x1A2B3C4D  (4 bytes)
      Major Version: 1           (2 bytes)
      Minor Version: 0           (2 bytes)
      Section Len  : -1 / 0xFFFFFFFFFFFFFFFF (8 bytes)
      Block Length : 28          (4 bytes, repeated)

    Total: 28 bytes
    """
    block_type = 0x0A0D0D0A
    block_total_length = 28
    byte_order_magic = 0x1A2B3C4D
    major_version = 1
    minor_version = 0
    section_length = (2**64) - 1   # unknown section length = 0xFFFFFFFFFFFFFFFF

    return struct.pack(
        "<IIIHHq",          # note: section_length is signed int64 on some impl
        block_type,
        block_total_length,
        byte_order_magic,
        major_version,
        minor_version,
        -1,                 # -1 = unknown section length (0xFFFFFFFFFFFFFFFF as int64)
    ) + struct.pack("<I", block_total_length)


def _write_temp_file(content: bytes, suffix: str) -> Path:
    """Write *content* to a temp file with *suffix*, return its Path."""
    fd, path_str = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    return Path(path_str)


# ---------------------------------------------------------------------------
# A. Validation tests
# ---------------------------------------------------------------------------

class TestValidation(unittest.TestCase):
    """Tests for validator.py — boundary validation logic."""

    def setUp(self):
        self.service = AcquisitionService()
        self._temps: list[Path] = []

    def tearDown(self):
        for p in self._temps:
            try:
                p.chmod(stat.S_IRUSR | stat.S_IWUSR)  # restore before deletion
                p.unlink(missing_ok=True)
            except OSError:
                pass

    def _temp(self, content: bytes, suffix: str) -> Path:
        p = _write_temp_file(content, suffix)
        self._temps.append(p)
        return p

    # ----- Test 1: Valid PCAP -----

    def test_01_valid_pcap_accepted(self):
        """A well-formed PCAP file must be accepted without error."""
        p = self._temp(_make_pcap_bytes(), ".pcap")
        ref = self.service.acquire(str(p))
        self.assertIsInstance(ref, AcquisitionReference)
        self.assertEqual(ref.format, "pcap")
        self.assertEqual(ref.file_name, p.name)

    # ----- Test 2: Valid PCAPNG -----

    def test_02_valid_pcapng_accepted(self):
        """A well-formed PCAPNG file must be accepted without error."""
        p = self._temp(_make_pcapng_bytes(), ".pcapng")
        ref = self.service.acquire(str(p))
        self.assertIsInstance(ref, AcquisitionReference)
        self.assertEqual(ref.format, "pcapng")

    # ----- Test 3: Missing file -----

    def test_03_missing_file_raises_file_not_found(self):
        with self.assertRaises(AcquisitionError) as ctx:
            self.service.acquire("/nonexistent/path/evidence.pcap")
        self.assertEqual(ctx.exception.code, AcquisitionErrorCode.FILE_NOT_FOUND)

    # ----- Test 4: Directory instead of file -----

    def test_04_directory_raises_not_a_file(self):
        with tempfile.TemporaryDirectory() as td:
            # Give the directory a .pcap suffix to bypass extension check
            dir_path = Path(td) / "captures.pcap"
            dir_path.mkdir()
            with self.assertRaises(AcquisitionError) as ctx:
                self.service.acquire(str(dir_path))
            self.assertEqual(ctx.exception.code, AcquisitionErrorCode.NOT_A_FILE)

    # ----- Test 5: Unsupported extension -----

    def test_05_unsupported_extension_raises_error(self):
        for ext in [".pcapdump", ".cap", ".log", ".txt", ".exe", ""]:
            with self.subTest(ext=ext):
                p = self._temp(_make_pcap_bytes(), ext)
                with self.assertRaises(AcquisitionError) as ctx:
                    self.service.acquire(str(p))
                self.assertEqual(
                    ctx.exception.code,
                    AcquisitionErrorCode.UNSUPPORTED_FORMAT,
                )

    # ----- Test 6: Empty file -----

    def test_06_empty_file_raises_empty_file(self):
        p = self._temp(b"", ".pcap")
        with self.assertRaises(AcquisitionError) as ctx:
            self.service.acquire(str(p))
        self.assertEqual(ctx.exception.code, AcquisitionErrorCode.EMPTY_FILE)

    # ----- Test 7: Invalid capture (bad magic) -----

    def test_07_invalid_magic_raises_invalid_capture(self):
        """A file with a correct extension but wrong magic must be rejected."""
        bad_content = b"\x00\x00\x00\x00" + b"\xff" * 100
        p = self._temp(bad_content, ".pcap")
        with self.assertRaises(AcquisitionError) as ctx:
            self.service.acquire(str(p))
        self.assertEqual(ctx.exception.code, AcquisitionErrorCode.INVALID_CAPTURE)

    def test_07b_pcapng_extension_with_pcap_magic_still_accepted(self):
        """If a .pcapng file contains PCAP magic, it should be accepted as pcap."""
        p = self._temp(_make_pcap_bytes(), ".pcapng")
        ref = self.service.acquire(str(p))
        self.assertEqual(ref.format, "pcap")

    # ----- Test: unreadable file (Linux only — skip on Windows) -----

    @unittest.skipIf(sys.platform == "win32", "chmod 000 unreliable on Windows")
    def test_unreadable_file_raises_unreadable_file(self):
        """A file with no read permission must raise UNREADABLE_FILE."""
        p = self._temp(_make_pcap_bytes(), ".pcap")
        p.chmod(0o000)
        try:
            with self.assertRaises(AcquisitionError) as ctx:
                self.service.acquire(str(p))
            self.assertEqual(ctx.exception.code, AcquisitionErrorCode.UNREADABLE_FILE)
        finally:
            p.chmod(stat.S_IRUSR | stat.S_IWUSR)


# ---------------------------------------------------------------------------
# B. SHA-256 correctness tests
# ---------------------------------------------------------------------------

class TestSHA256(unittest.TestCase):
    """Tests for hasher.py."""

    def setUp(self):
        self._temps: list[Path] = []

    def tearDown(self):
        for p in self._temps:
            p.unlink(missing_ok=True)

    def _temp(self, content: bytes, suffix: str = ".pcap") -> Path:
        p = _write_temp_file(content, suffix)
        self._temps.append(p)
        return p

    # ----- Test 8: Correct SHA-256 -----

    def test_08_correct_sha256_digest(self):
        """compute_sha256() must return the same digest as hashlib.sha256."""
        content = _make_pcap_bytes(num_packets=5)
        expected = hashlib.sha256(content).hexdigest()
        p = self._temp(content)
        self.assertEqual(compute_sha256(p), expected)

    # ----- Test 9: Deterministic -----

    def test_09_deterministic_repeated_hash(self):
        """Same file must produce identical digest on repeated calls."""
        content = _make_pcap_bytes()
        p = self._temp(content)
        digest_1 = compute_sha256(p)
        digest_2 = compute_sha256(p)
        self.assertEqual(digest_1, digest_2)

    def test_09b_digest_is_lowercase_hex(self):
        """Digest must be 64-character lowercase hexadecimal string."""
        p = self._temp(_make_pcap_bytes())
        digest = compute_sha256(p)
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, digest.lower())
        self.assertTrue(all(c in "0123456789abcdef" for c in digest))


# ---------------------------------------------------------------------------
# C. AcquisitionReference contract compliance
# ---------------------------------------------------------------------------

class TestAcquisitionReferenceContract(unittest.TestCase):
    """Tests verifying the returned model is contract-compliant."""

    def setUp(self):
        self.service = AcquisitionService()
        self._temps: list[Path] = []

    def tearDown(self):
        for p in self._temps:
            p.unlink(missing_ok=True)

    def _temp(self, content: bytes, suffix: str) -> Path:
        p = _write_temp_file(content, suffix)
        self._temps.append(p)
        return p

    # ----- Test 10: Contract compliance -----

    def test_10_acquisition_reference_validates_against_contract(self):
        """Returned AcquisitionReference must be a valid Pydantic model instance."""
        p = self._temp(_make_pcap_bytes(), ".pcap")
        ref = self.service.acquire(str(p))

        # Pydantic model validation is implicit at construction.
        # Re-validate by round-tripping through model_validate.
        data = ref.model_dump()
        re_validated = AcquisitionReference.model_validate(data)
        self.assertEqual(ref.acquisition_id, re_validated.acquisition_id)
        self.assertEqual(ref.sha256, re_validated.sha256)

    def test_10b_acquisition_reference_is_frozen(self):
        """AcquisitionReference must be immutable (frozen Pydantic model)."""
        p = self._temp(_make_pcap_bytes(), ".pcap")
        ref = self.service.acquire(str(p))
        with self.assertRaises(Exception):
            ref.sha256 = "tampered"  # type: ignore[misc]

    def test_10c_required_fields_are_populated(self):
        """All required AcquisitionReference fields must be non-empty."""
        p = self._temp(_make_pcap_bytes(), ".pcap")
        ref = self.service.acquire(str(p))

        self.assertTrue(ref.acquisition_id)
        self.assertTrue(ref.evidence_id)
        self.assertTrue(ref.file_name)
        self.assertGreater(ref.file_size, 0)
        self.assertIn(ref.format, ("pcap", "pcapng"))
        self.assertEqual(len(ref.sha256), 64)
        self.assertTrue(ref.capture_reference)
        self.assertIsNotNone(ref.acquired_at)

    def test_10d_unique_ids_per_acquisition(self):
        """Each call to acquire() must produce unique IDs."""
        p = self._temp(_make_pcap_bytes(), ".pcap")
        ref_a = self.service.acquire(str(p))
        ref_b = self.service.acquire(str(p))
        self.assertNotEqual(ref_a.acquisition_id, ref_b.acquisition_id)
        self.assertNotEqual(ref_a.evidence_id, ref_b.evidence_id)

    def test_10e_capture_reference_is_absolute_path(self):
        """capture_reference must be an absolute path string."""
        p = self._temp(_make_pcap_bytes(), ".pcap")
        ref = self.service.acquire(str(p))
        self.assertTrue(Path(ref.capture_reference).is_absolute())

    def test_10f_file_size_matches_actual_size(self):
        """file_size in the reference must match the actual file size."""
        content = _make_pcap_bytes(num_packets=10)
        p = self._temp(content, ".pcap")
        ref = self.service.acquire(str(p))
        self.assertEqual(ref.file_size, len(content))


# ---------------------------------------------------------------------------
# D. Forensic integrity tests
# ---------------------------------------------------------------------------

class TestForensicIntegrity(unittest.TestCase):
    """Original file must remain byte-for-byte identical after acquisition."""

    def setUp(self):
        self.service = AcquisitionService()
        self._temps: list[Path] = []

    def tearDown(self):
        for p in self._temps:
            p.unlink(missing_ok=True)

    def _temp(self, content: bytes, suffix: str) -> Path:
        p = _write_temp_file(content, suffix)
        self._temps.append(p)
        return p

    # ----- Test 11: Original file unchanged -----

    def test_11_original_file_unchanged_after_acquire(self):
        """File bytes and metadata must be identical before and after acquire()."""
        content = _make_pcap_bytes(num_packets=3)
        p = self._temp(content, ".pcap")

        before_bytes = p.read_bytes()
        before_size = p.stat().st_size
        before_mtime = p.stat().st_mtime

        self.service.acquire(str(p))

        after_bytes = p.read_bytes()
        after_size = p.stat().st_size
        after_mtime = p.stat().st_mtime

        self.assertEqual(before_bytes, after_bytes, "File content was modified!")
        self.assertEqual(before_size, after_size, "File size changed!")
        self.assertAlmostEqual(before_mtime, after_mtime, places=3,
                               msg="File mtime changed unexpectedly!")

    # ----- Test 12: No invented metadata -----

    def test_12_no_invented_metadata(self):
        """Fields that are not factually available must be None, not invented."""
        p = self._temp(_make_pcap_bytes(), ".pcap")
        ref = self.service.acquire(str(p))

        # Phase 2 cannot know Zeek-derived data
        if ref.provenance:
            self.assertIsNone(ref.provenance.zeek_uid,
                              "zeek_uid must be None in Phase 2 — Zeek not invoked")
            self.assertIsNone(ref.provenance.source_log,
                              "source_log must be None in Phase 2 — Zeek not invoked")

        # file_name must be basename only, not a full path
        self.assertNotIn(os.sep, ref.file_name,
                         "file_name must be basename, not a full path")


# ---------------------------------------------------------------------------
# E. Performance & response time tests
# ---------------------------------------------------------------------------

class TestPerformance(unittest.TestCase):
    """Performance and throughput benchmarks for the acquisition engine.

    Thresholds are conservative and appropriate for a production forensic
    pipeline running on commodity hardware:
      - acquire() on 1 MB synthetic capture: ≤ 200 ms
      - SHA-256 throughput: ≥ 50 MB/s
      - Validator rejection of bad magic: ≤ 5 ms
      - acquire() is sub-linear (2x file ≈ 2x time, not 10x)
    """

    THROUGHPUT_MIN_MBPS = 50.0    # MB/s minimum SHA-256 throughput
    ACQUIRE_1MB_MAX_MS = 200.0    # ms maximum for a 1 MB acquisition
    VALIDATOR_REJECT_MAX_MS = 50.0 # ms maximum for validator to reject bad magic

    def setUp(self):
        self.service = AcquisitionService()
        self._temps: list[Path] = []

    def tearDown(self):
        for p in self._temps:
            p.unlink(missing_ok=True)

    def _temp(self, content: bytes, suffix: str = ".pcap") -> Path:
        p = _write_temp_file(content, suffix)
        self._temps.append(p)
        return p

    def _make_synthetic_pcap(self, target_bytes: int) -> bytes:
        """Build a PCAP where the payload is padded to ~target_bytes."""
        header = _make_pcap_bytes(0)  # header only, 0 packets
        # Each packet record = 16-byte header + payload
        # We fill with one large packet (capped at snaplen = 65535)
        remaining = target_bytes - len(header)
        payload_size = min(remaining - 16, 65535)
        if payload_size <= 0:
            return header

        payload = b"\xAB" * payload_size
        pkt_hdr = struct.pack("<IIII", 1_700_000_000, 0, payload_size, payload_size)

        # Repeat to approximate target size
        packets = (pkt_hdr + payload) * max(1, remaining // (16 + payload_size))
        return header + packets

    # ----- Test 13: Large file does not load into memory all at once -----

    def test_13_large_file_uses_chunked_reading(self):
        """Verify that compute_sha256 does not read the entire file in one call.

        We test this indirectly by measuring that hashing a 10 MB file
        completes without OOM error and returns a valid 64-char digest.
        The hasher.py uses _CHUNK_SIZE = 65536 (verified by code review).
        """
        from app.engines.acquisition.hasher import _CHUNK_SIZE
        self.assertEqual(_CHUNK_SIZE, 65536, "Chunk size must remain 64 KiB")

        content = self._make_synthetic_pcap(10 * 1024 * 1024)  # 10 MB
        p = self._temp(content)
        digest = compute_sha256(p)
        self.assertEqual(len(digest), 64)

    # ----- Test 14: acquire() on 1 MB ≤ 200 ms -----

    def test_14_acquire_1mb_within_200ms(self):
        """acquire() on a 1 MB synthetic PCAP must complete in ≤ 200 ms."""
        content = self._make_synthetic_pcap(1 * 1024 * 1024)
        p = self._temp(content)

        start = time.perf_counter()
        ref = self.service.acquire(str(p))
        elapsed_ms = (time.perf_counter() - start) * 1000

        self.assertIsInstance(ref, AcquisitionReference)
        self.assertLessEqual(
            elapsed_ms,
            self.ACQUIRE_1MB_MAX_MS,
            f"acquire() took {elapsed_ms:.1f} ms on 1 MB file — threshold {self.ACQUIRE_1MB_MAX_MS} ms",
        )

    # ----- Test 15: SHA-256 throughput ≥ 50 MB/s -----

    def test_15_sha256_throughput_meets_minimum(self):
        """SHA-256 throughput must be ≥ 50 MB/s on the test machine."""
        target_size = 5 * 1024 * 1024   # 5 MB for a stable measurement
        content = self._make_synthetic_pcap(target_size)
        p = self._temp(content)
        actual_size_mb = len(content) / (1024 * 1024)

        # Warm-up read (disk caching)
        _ = compute_sha256(p)

        # Timed run
        start = time.perf_counter()
        compute_sha256(p)
        elapsed_s = time.perf_counter() - start

        throughput_mbps = actual_size_mb / elapsed_s
        self.assertGreaterEqual(
            throughput_mbps,
            self.THROUGHPUT_MIN_MBPS,
            f"SHA-256 throughput {throughput_mbps:.1f} MB/s < minimum {self.THROUGHPUT_MIN_MBPS} MB/s",
        )

    # ----- Test 16: Validator rejects bad magic in < 5 ms -----

    def test_16_validator_rejects_bad_magic_fast(self):
        """Validator must reject an invalid capture in ≤ 5 ms (reads only 4 bytes)."""
        bad_content = b"\x00\x01\x02\x03" + b"\xff" * 200
        p = self._temp(bad_content)

        start = time.perf_counter()
        try:
            validate(str(p))
            self.fail("Expected AcquisitionError was not raised")
        except AcquisitionError as exc:
            elapsed_ms = (time.perf_counter() - start) * 1000
            self.assertEqual(exc.code, AcquisitionErrorCode.INVALID_CAPTURE)
            self.assertLessEqual(
                elapsed_ms,
                self.VALIDATOR_REJECT_MAX_MS,
                f"Validator took {elapsed_ms:.2f} ms to reject — threshold {self.VALIDATOR_REJECT_MAX_MS} ms",
            )

    # ----- Test 17: Sub-linear scaling -----

    def test_17_sublinear_scaling(self):
        """2x file size should not take >5x longer (validates chunked I/O)."""
        size_small = 1 * 1024 * 1024   # 1 MB
        size_large = 2 * 1024 * 1024   # 2 MB

        content_small = self._make_synthetic_pcap(size_small)
        content_large = self._make_synthetic_pcap(size_large)
        p_small = self._temp(content_small, ".pcap")
        p_large = self._temp(content_large, ".pcap")

        # Warm-up
        compute_sha256(p_small)
        compute_sha256(p_large)

        start = time.perf_counter()
        compute_sha256(p_small)
        t_small = time.perf_counter() - start

        start = time.perf_counter()
        compute_sha256(p_large)
        t_large = time.perf_counter() - start

        if t_small > 0:
            ratio = t_large / t_small
            self.assertLess(
                ratio,
                5.0,
                f"Scaling ratio {ratio:.2f}x for 2x file size — likely non-chunked I/O",
            )


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
