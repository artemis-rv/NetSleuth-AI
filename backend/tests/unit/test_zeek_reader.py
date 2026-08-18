"""
backend/tests/unit/test_zeek_reader.py
--------------------------------------
Unit tests for the Phase 4 Zeek Reader.
"""

from __future__ import annotations

import os
import shutil
import struct
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from typing import Generator

from app.contracts.network_intelligence import AcquisitionReference, Provenance
from app.engines.packet_intelligence.zeek import (
    RawZeekErrorRecord,
    RawZeekRecord,
    ZeekReader,
    ZeekRunner,
    ZeekRunnerError,
    ZeekRunnerErrorCode,
    ZeekRunnerResult,
    ZeekRunnerStatus,
)


def _make_pcap_bytes() -> bytes:
    """Build a minimal valid PCAP file."""
    global_hdr = struct.pack(
        "<IHHiIII",
        0xA1B2C3D4,  # magic
        2, 4,        # version 2.4
        0, 0, 65535, 1,
    )
    payload = bytes(64)
    ts_sec = 1_700_000_000
    ts_usec = 0
    incl_len = len(payload)
    orig_len = len(payload)
    pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, incl_len, orig_len)
    return global_hdr + pkt_hdr + payload


class TestZeekReader(unittest.TestCase):
    """Test suite for ZeekReader boundary behavior."""

    def setUp(self):
        self.acquisition_id = "acq-12345"
        from unittest.mock import MagicMock
        self.mock_storage = MagicMock()
        self.reader = ZeekReader(storage=self.mock_storage)

    def tearDown(self):
        pass

    def _setup_mock_stream(self, content: str) -> None:
        from contextlib import contextmanager
        @contextmanager
        def mock_stream_file(object_key: str):
            lines = content.split('\n')
            if lines and not lines[-1]:
                lines.pop()
            yield lines
        self.mock_storage.stream_file = mock_stream_file

    def _create_mock_result(self, generated_logs: list[str]) -> ZeekRunnerResult:
        return ZeekRunnerResult(
            acquisition_id=self.acquisition_id,
            status=ZeekRunnerStatus.SUCCESS,
            bucket="test-zeek-bucket",
            prefix=f"zeek/{self.acquisition_id}/",
            generated_objects=generated_logs,
            exit_code=0,
            execution_duration_s=1.0,
            zeek_image="zeek/zeek:lts",
            zeek_version="8.0.0",
            stderr_tail="",
        )

    def test_valid_json_log(self):
        """Test reading a valid JSON log with multiple records."""
        content = (
            '{"ts": 1700000000.0, "uid": "C123", "id.orig_h": "10.0.0.1"}\n'
            '{"ts": 1700000001.0, "uid": "C456", "id.orig_h": "10.0.0.2"}\n'
        )
        self._setup_mock_stream(content)
        result = self._create_mock_result([f"zeek/{self.acquisition_id}/conn.log"])

        records = list(self.reader.read(result))

        self.assertEqual(len(records), 2)
        self.assertIsInstance(records[0], RawZeekRecord)
        self.assertEqual(records[0].log_type, "conn")
        self.assertEqual(records[0].source_log, "conn.log")
        self.assertEqual(records[0].line_number, 1)
        self.assertEqual(records[0].record["uid"], "C123")

        self.assertIsInstance(records[1], RawZeekRecord)
        self.assertEqual(records[1].line_number, 2)
        self.assertEqual(records[1].record["uid"], "C456")

    def test_empty_log(self):
        """Test that an empty log yields no records without crashing."""
        self._setup_mock_stream("")
        result = self._create_mock_result([f"zeek/{self.acquisition_id}/dns.log"])

        records = list(self.reader.read(result))
        self.assertEqual(len(records), 0)

    def test_missing_log(self):
        """Test that a log listed in generated_logs but missing from disk is skipped."""
        # We do NOT create "http.log" on disk
        result = self._create_mock_result(["http.log"])

        records = list(self.reader.read(result))
        self.assertEqual(len(records), 0)

    def test_metadata_header_handling(self):
        """Test that lines starting with `#` are safely ignored."""
        content = (
            '#separator \\x09\n'
            '#set_separator\t,\n'
            '{"ts": 1700000000.0, "uid": "C123"}\n'
            '#close\t2023-11-15\n'
        )
        self._setup_mock_stream(content)
        result = self._create_mock_result([f"zeek/{self.acquisition_id}/conn.log"])

        records = list(self.reader.read(result))
        self.assertEqual(len(records), 1)
        self.assertIsInstance(records[0], RawZeekRecord)
        self.assertEqual(records[0].line_number, 3)
        self.assertEqual(records[0].record["uid"], "C123")

    def test_malformed_json_line_recovery(self):
        """Test that a bad JSON line yields an error record but processing continues."""
        content = (
            '{"ts": 1700000000.0, "uid": "C123"}\n'
            '{"ts": 1700000001.0, "uid": "C456, MISSING_QUOTE}\n'
            '{"ts": 1700000002.0, "uid": "C789"}\n'
        )
        self._setup_mock_stream(content)
        result = self._create_mock_result([f"zeek/{self.acquisition_id}/conn.log"])

        records = list(self.reader.read(result))
        self.assertEqual(len(records), 3)

        self.assertIsInstance(records[0], RawZeekRecord)
        self.assertEqual(records[0].line_number, 1)

        self.assertIsInstance(records[1], RawZeekErrorRecord)
        self.assertEqual(records[1].line_number, 2)
        self.assertEqual(records[1].error_type, "JSON_DECODE_ERROR")

        self.assertIsInstance(records[2], RawZeekRecord)
        self.assertEqual(records[2].line_number, 3)

    def test_invalid_record_type(self):
        """Test that valid JSON which isn't a dict is treated as an error."""
        content = (
            '{"ts": 1700000000.0}\n'
            '["not", "a", "dict"]\n'
            '42\n'
        )
        self._setup_mock_stream(content)
        result = self._create_mock_result([f"zeek/{self.acquisition_id}/weird.log"])

        records = list(self.reader.read(result))
        self.assertEqual(len(records), 3)
        self.assertIsInstance(records[0], RawZeekRecord)
        self.assertIsInstance(records[1], RawZeekErrorRecord)
        self.assertEqual(records[1].error_type, "INVALID_RECORD_TYPE")
        self.assertIsInstance(records[2], RawZeekErrorRecord)
        self.assertEqual(records[2].error_type, "INVALID_RECORD_TYPE")

    def test_metadata_preservation(self):
        """Test that acquisition_id, log_type, and line_number are strictly preserved."""
        content = '{"ts": 1.0}\n'
        self._setup_mock_stream(content)
        result = self._create_mock_result([f"zeek/{self.acquisition_id}/x509.log"])

        records = list(self.reader.read(result))
        self.assertEqual(len(records), 1)
        record = records[0]
        self.assertIsInstance(record, RawZeekRecord)
        self.assertEqual(record.acquisition_id, self.acquisition_id)
        self.assertEqual(record.log_type, "x509")
        self.assertEqual(record.source_log, "x509.log")
        self.assertEqual(record.line_number, 1)

    def test_multiple_different_log_types(self):
        """Test reading multiple different log files sequentially."""
        self._setup_mock_stream('{"uid": "1"}\n{"uid": "2"}\n')
        result = self._create_mock_result([f"zeek/{self.acquisition_id}/conn.log", f"zeek/{self.acquisition_id}/dns.log"])
        
        records = list(self.reader.read(result))
        self.assertEqual(len(records), 4)
        
        self.assertEqual(records[0].log_type, "conn")
        self.assertEqual(records[0].record["uid"], "1")
        self.assertEqual(records[1].log_type, "conn")
        self.assertEqual(records[1].record["uid"], "2")
        
        self.assertEqual(records[2].log_type, "dns")
        self.assertEqual(records[2].record["uid"], "1")
        self.assertEqual(records[3].log_type, "dns")
        self.assertEqual(records[3].record["uid"], "2")

    def test_memory_efficiency(self):
        """Verify the reader yields incrementally and doesn't read the whole file."""
        content = '{"ts": 1.0}\n{"ts": 2.0}\n'
        self._setup_mock_stream(content)
        result = self._create_mock_result([f"zeek/{self.acquisition_id}/conn.log"])

        generator = self.reader.read(result)
        self.assertIsInstance(generator, Generator)
        
        first = next(generator)
        self.assertEqual(first.line_number, 1)
        # We can stop reading here without consuming the rest of the file


class TestZeekReaderIntegration(unittest.TestCase):
    """Integration test validating ZeekReader consumes ZeekRunner output."""

    def setUp(self):
        import tempfile
        self.evidence_temp = tempfile.mkdtemp()
        from unittest.mock import MagicMock
        from contextlib import contextmanager
        self.mock_storage = MagicMock()
        self.mock_storage.bucket_name = "test-zeek-bucket"
        self.in_memory_files = {}
        
        def mock_upload_file(file_path, object_key):
            with open(file_path, 'r', encoding='utf-8') as f:
                self.in_memory_files[object_key] = f.read()
        self.mock_storage.upload_file = mock_upload_file
        
        @contextmanager
        def mock_stream_file(object_key: str):
            content = self.in_memory_files.get(object_key, "")
            lines = content.split('\n')
            if lines and not lines[-1]:
                lines.pop()
            yield lines
        self.mock_storage.stream_file = mock_stream_file

        self.runner = ZeekRunner(storage=self.mock_storage)
        self.reader = ZeekReader(storage=self.mock_storage)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.evidence_temp, ignore_errors=True)

    @unittest.skipIf(not shutil.which("docker"), "Docker not installed")
    def test_integration_runner_to_reader(self):
        """End-to-End: ZeekRunner produces logs -> ZeekReader consumes them."""
        # 1. Create a real PCAP
        pcap_path = Path(self.evidence_temp) / "test.pcap"
        pcap_path.write_bytes(_make_pcap_bytes())

        # 2. Create reference
        ref = AcquisitionReference(
            acquisition_id="acq-int-123",
            evidence_id="ev-int-123",
            file_name="test.pcap",
            file_size=pcap_path.stat().st_size,
            format="pcap",
            sha256="dummyhash",
            capture_reference=str(pcap_path),
            acquired_at=datetime.now(timezone.utc),
            provenance=Provenance(
                acquisition_id="acq-int-123",
                evidence_id="ev-int-123",
                source="test",
            ),
        )

        # 3. Run ZeekRunner
        runner_result = self.runner.run(ref)
        self.assertEqual(runner_result.status, ZeekRunnerStatus.SUCCESS)
        self.assertGreater(len(runner_result.generated_objects), 0)

        # 4. Read logs via ZeekReader
        records = list(self.reader.read(runner_result))

        # 5. Verify records
        self.assertGreater(len(records), 0)
        
        # Verify no error records were produced (since these are fresh Zeek logs)
        error_records = [r for r in records if isinstance(r, RawZeekErrorRecord)]
        self.assertEqual(len(error_records), 0, f"Unexpected errors: {error_records}")

        # Verify all are valid RawZeekRecord objects
        valid_records = [r for r in records if isinstance(r, RawZeekRecord)]
        self.assertEqual(len(valid_records), len(records))

        # Check that we have expected metadata structure
        for rec in valid_records:
            self.assertEqual(rec.acquisition_id, "acq-int-123")
            self.assertIsInstance(rec.record, dict)
            self.assertIn(rec.log_type, rec.source_log)
            # 'ts' field is virtually universal in Zeek logs
            self.assertIn("ts", rec.record)


if __name__ == "__main__":
    unittest.main()
