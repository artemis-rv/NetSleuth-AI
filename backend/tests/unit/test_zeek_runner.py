"""
backend/tests/unit/test_zeek_runner.py
--------------------------------------
Unit and integration tests for Phase 3 Zeek Runner.
"""

from __future__ import annotations

import json
import os
import shutil
import struct
import subprocess
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

from app.contracts.network_intelligence import AcquisitionReference, Provenance
from app.engines.packet_intelligence.zeek import (
    ZeekRunner,
    ZeekRunnerError,
    ZeekRunnerErrorCode,
    ZeekRunnerStatus,
)


# ---------------------------------------------------------------------------
# Synthetic PCAP/PCAPNG Builders (from Phase 2 patterns)
# ---------------------------------------------------------------------------

def _make_pcap_bytes() -> bytes:
    """Build a minimal valid PCAP file."""
    # Global header (24 bytes)
    global_hdr = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic
        2, 4,        # version 2.4
        0, 0, 65535, 1,
    )
    # Per-packet record header (16 bytes) + minimal payload
    # Let's add a dummy ethernet/IP/TCP structure to trigger logs if possible
    payload = bytes(64)
    ts_sec = 1_700_000_000
    ts_usec = 0
    incl_len = len(payload)
    orig_len = len(payload)
    pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
    return global_hdr + pkt_hdr + payload


def _make_pcapng_bytes() -> bytes:
    """Build a minimal valid PCAPNG file (SHB + IDB)."""
    # 1. SHB Block (28 bytes)
    block_type = 0x0A0D0D0A
    block_total_length = 28
    byte_order_magic = 0x1A2B3C4D
    major_version = 1
    minor_version = 0
    shb = struct.pack(
        "<IIIHHq",
        block_type, block_total_length, byte_order_magic,
        major_version, minor_version, -1,
    ) + struct.pack("<I", block_total_length)
    
    # 2. IDB Block (20 bytes)
    idb_type = 0x00000001
    idb_len = 20
    link_type = 1
    reserved = 0
    snap_len = 65535
    idb = struct.pack(
        "<IIHHI",
        idb_type, idb_len, link_type, reserved, snap_len
    ) + struct.pack("<I", idb_len)
    
    return shb + idb


def _write_temp_file(content: bytes, suffix: str) -> Path:
    fd, path_str = tempfile.mkstemp(suffix=suffix)
    try:
        os.write(fd, content)
    finally:
        os.close(fd)
    return Path(path_str)


# ---------------------------------------------------------------------------
# Test Suite
# ---------------------------------------------------------------------------

class TestZeekRunner(unittest.TestCase):
    """Test suite for ZeekRunner."""

    def setUp(self):
        self._temps: list[Path] = []
        self.output_root_temp = tempfile.mkdtemp()
        self._temps.append(Path(self.output_root_temp))

        # Setup base runner targeting the temp output root
        self.runner = ZeekRunner(output_root=self.output_root_temp)

    def tearDown(self):
        for p in self._temps:
            try:
                if p.is_dir():
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    p.unlink(missing_ok=True)
            except OSError:
                pass

    def _temp_file(self, content: bytes, suffix: str) -> Path:
        p = _write_temp_file(content, suffix)
        self._temps.append(p)
        return p

    def _make_mock_ref(self, capture_path: Path) -> AcquisitionReference:
        return AcquisitionReference(
            acquisition_id="acq-12345",
            evidence_id="ev-12345",
            file_name=capture_path.name,
            file_size=capture_path.stat().st_size,
            format="pcap" if capture_path.suffix == ".pcap" else "pcapng",
            sha256="da39a3ee5e6b4b0d3255bfef95601890afd80709",
            capture_reference=str(capture_path),
            acquired_at=datetime.now(timezone.utc),
            provenance=Provenance(
                acquisition_id="acq-12345",
                evidence_id="ev-12345",
                source="test",
            ),
        )

    # =======================================================================
    # Unit Tests (Mocked Subprocess)
    # =======================================================================

    @patch("shutil.which")
    def test_docker_missing_raises_error(self, mock_which):
        """If docker executable is not found, raise DOCKER_NOT_FOUND."""
        mock_which.return_value = None
        p = self._temp_file(_make_pcap_bytes(), ".pcap")
        ref = self._make_mock_ref(p)

        with self.assertRaises(ZeekRunnerError) as ctx:
            self.runner.run(ref)
        self.assertEqual(ctx.exception.code, ZeekRunnerErrorCode.DOCKER_NOT_FOUND)

    @patch("subprocess.run")
    def test_docker_daemon_unavailable_raises_error(self, mock_run):
        """If docker daemon check fails, raise DOCKER_DAEMON_UNAVAILABLE."""
        # First call mock for check_docker_env -> docker info
        mock_run.return_value = MagicMock(returncode=1, stderr=b"daemon not running")
        p = self._temp_file(_make_pcap_bytes(), ".pcap")
        ref = self._make_mock_ref(p)

        with self.assertRaises(ZeekRunnerError) as ctx:
            self.runner.run(ref)
        self.assertEqual(ctx.exception.code, ZeekRunnerErrorCode.DOCKER_DAEMON_UNAVAILABLE)

    @patch("subprocess.run")
    def test_image_unavailable_raises_error(self, mock_run):
        """If docker image is unavailable or version check fails, raise IMAGE_UNAVAILABLE."""
        # check_docker_env passes, but zeek --version fails
        mock_run.side_effect = [
            MagicMock(returncode=0),  # docker info
            MagicMock(returncode=1, stderr="image not found"),  # zeek --version
        ]
        p = self._temp_file(_make_pcap_bytes(), ".pcap")
        ref = self._make_mock_ref(p)

        with self.assertRaises(ZeekRunnerError) as ctx:
            self.runner.run(ref)
        self.assertEqual(ctx.exception.code, ZeekRunnerErrorCode.IMAGE_UNAVAILABLE)

    def test_missing_capture_file_raises_error(self):
        """If the capture file referenced does not exist, raise CAPTURE_NOT_FOUND."""
        ref = AcquisitionReference(
            acquisition_id="acq-123",
            evidence_id="ev-123",
            file_name="missing.pcap",
            file_size=100,
            format="pcap",
            sha256="abc",
            capture_reference="/tmp/missing.pcap",
            acquired_at=datetime.now(timezone.utc),
        )
        with self.assertRaises(ZeekRunnerError) as ctx:
            self.runner.run(ref)
        self.assertEqual(ctx.exception.code, ZeekRunnerErrorCode.CAPTURE_NOT_FOUND)

    def test_path_traversal_attempt_blocked(self):
        """If capture file is outside allowed roots, raise PATH_TRAVERSAL_DETECTED."""
        # Setup runner with constrained roots that EXCLUDE the system temp directory
        restricted_runner = ZeekRunner(
            output_root=self.output_root_temp,
            allowed_evidence_roots=["/some/isolated/safe/path"],
        )
        p = self._temp_file(_make_pcap_bytes(), ".pcap")
        ref = self._make_mock_ref(p)

        with self.assertRaises(ZeekRunnerError) as ctx:
            restricted_runner.run(ref)
        self.assertEqual(ctx.exception.code, ZeekRunnerErrorCode.PATH_TRAVERSAL_DETECTED)

    @patch("subprocess.run")
    def test_docker_command_construction(self, mock_run):
        """Verify the Docker command arguments are built correctly."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # docker info
            MagicMock(returncode=0, stdout="zeek version 8.0.9\n"),  # zeek --version
            MagicMock(returncode=0),  # main execution run
        ]
        p = self._temp_file(_make_pcap_bytes(), ".pcap")
        ref = self._make_mock_ref(p)

        self.runner.run(ref)

        # Retrieve arguments from the third subprocess run
        executed_cmd = mock_run.call_args_list[2][0][0]
        self.assertEqual(executed_cmd[0], "docker")
        self.assertEqual(executed_cmd[1], "run")
        self.assertIn("--rm", executed_cmd)

        # Check read-only mount point
        evidence_mount = f"{p.parent}:/data/evidence:ro"
        self.assertIn("-v", executed_cmd)
        self.assertIn(evidence_mount, executed_cmd)

        # Check output mount
        expected_output_dir = Path(self.output_root_temp) / ref.acquisition_id
        output_mount = f"{expected_output_dir}:/data/output"
        self.assertIn(output_mount, executed_cmd)

        # Check JSON output option
        self.assertIn("LogAscii::use_json=T", executed_cmd)

    @patch("subprocess.run")
    def test_zeek_nonzero_exit_raises_error(self, mock_run):
        """If Zeek exits with a non-zero code, raise ZEEK_NONZERO_EXIT."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # docker info
            MagicMock(returncode=0, stdout="zeek version 8.0.9\n"),  # zeek --version
            MagicMock(returncode=2, stderr="Zeek crash details"),  # main execution
        ]
        p = self._temp_file(_make_pcap_bytes(), ".pcap")
        ref = self._make_mock_ref(p)

        with self.assertRaises(ZeekRunnerError) as ctx:
            self.runner.run(ref)
        self.assertEqual(ctx.exception.code, ZeekRunnerErrorCode.ZEEK_NONZERO_EXIT)

    @patch("subprocess.run")
    def test_zeek_timeout_raises_error(self, mock_run):
        """If Zeek execution times out, raise TIMEOUT."""
        mock_run.side_effect = [
            MagicMock(returncode=0),  # docker info
            MagicMock(returncode=0, stdout="zeek version 8.0.9\n"),  # zeek --version
            subprocess.TimeoutExpired(cmd=["docker", "run"], timeout=300),  # main execution
        ]
        p = self._temp_file(_make_pcap_bytes(), ".pcap")
        ref = self._make_mock_ref(p)

        with self.assertRaises(ZeekRunnerError) as ctx:
            self.runner.run(ref)
        self.assertEqual(ctx.exception.code, ZeekRunnerErrorCode.TIMEOUT)

    # =======================================================================
    # Integration Tests (Real Docker & Zeek Execution)
    # =======================================================================

    def test_integration_successful_pcap_run(self):
        """End-to-End run with a real PCAP, Docker container, and JSON verification."""
        p = self._temp_file(_make_pcap_bytes(), ".pcap")
        ref = self._make_mock_ref(p)

        # Perform the actual execution
        result = self.runner.run(ref)

        self.assertEqual(result.status, ZeekRunnerStatus.SUCCESS)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(result.output_directory.exists())
        self.assertGreater(result.execution_duration_s, 0)

        # Ensure the original PCAP remains untouched
        self.assertTrue(p.exists())
        self.assertEqual(p.stat().st_size, ref.file_size)

        # Expect logs (weird.log or packet_filter.log or conn.log depending on traffic)
        # Even with raw zeros, Zeek normally outputs packet_filter.log, loaded_scripts.log, etc.
        self.assertTrue(len(result.generated_logs) > 0)

        # Verify any generated log file contains valid JSON
        for log_name in result.generated_logs:
            log_file = result.output_directory / log_name
            with log_file.open("r", encoding="utf-8") as fh:
                first_line = fh.readline()
                if first_line.strip():
                    # Parse as JSON to assert LogAscii::use_json=T worked correctly
                    try:
                        parsed = json.loads(first_line)
                        self.assertIsInstance(parsed, dict)
                    except json.JSONDecodeError:
                        self.fail(f"Log {log_name} was not written in JSON format: {first_line}")

    def test_integration_successful_pcapng_run(self):
        """End-to-End run with a real PCAPNG capture."""
        p = self._temp_file(_make_pcapng_bytes(), ".pcapng")
        ref = self._make_mock_ref(p)

        result = self.runner.run(ref)

        self.assertEqual(result.status, ZeekRunnerStatus.SUCCESS)
        self.assertEqual(result.exit_code, 0)
        self.assertTrue(len(result.generated_logs) > 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
