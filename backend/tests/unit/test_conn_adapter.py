"""
backend/tests/unit/test_conn_adapter.py
---------------------------------------
Unit tests for the Phase 5 ConnAdapter.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
import struct
import tempfile
from pathlib import Path

from app.contracts.network_intelligence import AcquisitionReference, Flow, Provenance
from app.engines.packet_intelligence.adapters import AdapterError, AdapterErrorCode, ConnAdapter
from app.engines.packet_intelligence.zeek.reader import RawZeekRecord, ZeekReader
from app.engines.packet_intelligence.zeek import ZeekRunnerResult, ZeekRunnerStatus





class TestConnAdapter(unittest.TestCase):
    """Unit tests for ConnAdapter mapping boundary."""

    def setUp(self):
        self.adapter = ConnAdapter()
        self.acq_id = "test-acq-123"
        self.base_record = {
            "ts": 1700000000.0,
            "uid": "CHhAvVGS1DHF5r6w2",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49392,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 5.2,
            "orig_bytes": 1000,
            "resp_bytes": 5000,
            "orig_pkts": 10,
            "resp_pkts": 15,
            "conn_state": "SF",
        }

    def _make_raw(self, record_dict: dict, log_type: str = "conn") -> RawZeekRecord:
        return RawZeekRecord(
            acquisition_id=self.acq_id,
            source_log=f"{log_type}.log",
            log_type=log_type,
            record=record_dict,
            line_number=1,
        )

    def test_valid_tcp_connection(self):
        """Test valid standard TCP connection mapping."""
        raw = self._make_raw(self.base_record)
        result = self.adapter.convert(raw)

        self.assertIsInstance(result, Flow)
        self.assertIsNotNone(result.flow_id)
        self.assertEqual(result.zeek_uid, "CHhAvVGS1DHF5r6w2")
        self.assertEqual(result.source.ip, "192.168.1.100")
        self.assertEqual(result.source.port, 49392)
        self.assertEqual(result.destination.ip, "10.0.0.5")
        self.assertEqual(result.destination.port, 443)
        self.assertEqual(result.protocol, "tcp")
        self.assertEqual(result.service, "ssl")
        self.assertEqual(result.duration, 5.2)
        self.assertEqual(result.orig_bytes, 1000)
        self.assertEqual(result.resp_bytes, 5000)
        self.assertEqual(result.connection_state, "SF")
        self.assertEqual(result.timestamp, datetime(2023, 11, 14, 22, 13, 20, tzinfo=timezone.utc))
        self.assertIsNone(result.end_time)

    def test_valid_udp_connection(self):
        """Test valid standard UDP connection mapping."""
        record = self.base_record.copy()
        record["proto"] = "udp"
        record["id.resp_p"] = 53
        record["service"] = "dns"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw)

        self.assertIsInstance(result, Flow)
        self.assertEqual(result.protocol, "udp")
        self.assertEqual(result.destination.port, 53)
        self.assertEqual(result.service, "dns")

    def test_missing_required_fields(self):
        """Test missing uid and addresses."""
        keys_to_drop = ["uid", "id.orig_h", "id.resp_p", "proto"]
        for key in keys_to_drop:
            bad_record = self.base_record.copy()
            del bad_record[key]
            raw = self._make_raw(bad_record)
            
            result = self.adapter.convert(raw)
            self.assertIsInstance(result, AdapterError)
            self.assertEqual(result.code, AdapterErrorCode.MISSING_REQUIRED_FIELD)
            self.assertIn(key, result.message)

    def test_invalid_numeric_values(self):
        """Test invalid port or timestamp types."""
        bad_record = self.base_record.copy()
        bad_record["id.resp_p"] = "not_a_port"
        raw = self._make_raw(bad_record)
        
        result = self.adapter.convert(raw)
        self.assertIsInstance(result, AdapterError)
        self.assertEqual(result.code, AdapterErrorCode.INVALID_TYPE)

    def test_null_byte_counts(self):
        """Test '-' mapping to None."""
        record = self.base_record.copy()
        record["orig_bytes"] = "-"
        record["resp_bytes"] = None
        record["duration"] = "-"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw)
        
        self.assertIsInstance(result, Flow)
        self.assertIsNone(result.orig_bytes)
        self.assertIsNone(result.resp_bytes)
        self.assertIsNone(result.duration)

    def test_zero_bytes_counts(self):
        """Test 0 maps strictly to 0."""
        record = self.base_record.copy()
        record["orig_bytes"] = 0
        record["resp_bytes"] = 0
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw)
        
        self.assertIsInstance(result, Flow)
        self.assertEqual(result.orig_bytes, 0)
        self.assertEqual(result.resp_bytes, 0)

    def test_unsupported_log_type(self):
        """Test rejecting dns.log."""
        raw = self._make_raw(self.base_record, log_type="dns")
        result = self.adapter.convert(raw)
        
        self.assertIsInstance(result, AdapterError)
        self.assertEqual(result.code, AdapterErrorCode.UNSUPPORTED_LOG_TYPE)

    def test_provenance_preservation(self):
        """Test preservation of identities and provenance."""
        raw = self._make_raw(self.base_record)
        result = self.adapter.convert(raw)
        
        self.assertIsInstance(result, Flow)
        self.assertEqual(result.acquisition_id, self.acq_id)
        self.assertIsNone(result.evidence_id)
        
        prov = result.provenance
        self.assertEqual(prov.acquisition_id, self.acq_id)
        self.assertEqual(prov.zeek_uid, "CHhAvVGS1DHF5r6w2")
        self.assertEqual(prov.source, "zeek")
        self.assertEqual(prov.source_log, "conn.log")
        self.assertIsNotNone(prov.processed_at)

    def test_multiple_services(self):
        """Zeek can log multiple services separated by comma."""
        record = self.base_record.copy()
        record["service"] = "dns,mdns"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw)
        
        self.assertIsInstance(result, Flow)
        self.assertEqual(result.service, "dns,mdns")

    def test_invalid_contract_data(self):
        """Test that invalid values (e.g. port out of range) yield a MALFORMED_RECORD error."""
        record = self.base_record.copy()
        record["id.resp_p"] = 999999  # Out of range 0-65535
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw)
        
        self.assertIsInstance(result, AdapterError)
        self.assertEqual(result.code, AdapterErrorCode.MALFORMED_RECORD)


class TestConnAdapterIntegration(unittest.TestCase):
    """Integration test for Phase 4 (Reader) -> 5 (Adapter)."""

    def setUp(self):
        self.output_root_temp = tempfile.mkdtemp()
        self.output_dir = Path(self.output_root_temp)
        self.reader = ZeekReader()
        self.adapter = ConnAdapter()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.output_root_temp, ignore_errors=True)

    def test_integration_pipeline_to_flow(self):
        """End-to-End: JSON Log -> Reader -> conn.log -> Adapter -> Flow."""
        # 1. Create a mock conn.log
        conn_log_content = (
            '{"ts":1700000000.0,"uid":"C123","id.orig_h":"192.168.1.1","id.orig_p":1234,"id.resp_h":"1.1.1.1","id.resp_p":53,"proto":"udp","service":"dns","duration":0.01,"orig_bytes":50,"resp_bytes":50,"conn_state":"SF"}\n'
            '{"ts":1700000001.0,"uid":"C456","id.orig_h":"192.168.1.2","id.orig_p":5678,"id.resp_h":"8.8.8.8","id.resp_p":443,"proto":"tcp","service":"ssl","duration":5.0,"orig_bytes":1500,"resp_bytes":5000,"conn_state":"SF"}\n'
        )
        (self.output_dir / "conn.log").write_text(conn_log_content, encoding="utf-8")

        # 2. Mock Phase 3 result pointing to the directory
        runner_result = ZeekRunnerResult(
            acquisition_id="acq-int-456",
            status=ZeekRunnerStatus.SUCCESS,
            output_directory=self.output_dir,
            generated_logs=["conn.log"],
            exit_code=0,
            execution_duration_s=1.0,
            zeek_image="zeek/zeek:lts",
            zeek_version="8.0.0",
            stderr_tail="",
        )

        # 3. Stream records via Phase 4 reader
        flows = []
        errors = []
        for raw_record in self.reader.read(runner_result):
            if isinstance(raw_record, RawZeekRecord) and raw_record.log_type == "conn":
                # 4. Map via Phase 5 adapter
                flow_result = self.adapter.convert(raw_record)
                if isinstance(flow_result, Flow):
                    flows.append(flow_result)
                else:
                    errors.append(flow_result)

        self.assertEqual(len(flows), 2, "Expected exactly two Flow objects")
        self.assertEqual(len(errors), 0, "Did not expect mapping errors for valid JSON output")

        flow1 = flows[0]
        self.assertIsInstance(flow1, Flow)
        self.assertEqual(flow1.acquisition_id, "acq-int-456")
        self.assertIsNone(flow1.evidence_id)
        self.assertEqual(flow1.protocol, "udp")
        self.assertEqual(flow1.service, "dns")
        
        flow2 = flows[1]
        self.assertEqual(flow2.protocol, "tcp")
        self.assertEqual(flow2.service, "ssl")


if __name__ == "__main__":
    unittest.main()
