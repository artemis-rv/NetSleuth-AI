"""
backend/tests/unit/test_tls_adapter.py
--------------------------------------
Unit tests for the Phase 8 TLSAdapter.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.contracts.network_intelligence import ProtocolEvent, TLSData, Flow
from app.engines.packet_intelligence.adapters import AdapterError, AdapterErrorCode, TLSAdapter, ConnAdapter
from app.engines.packet_intelligence.zeek.reader import RawZeekRecord, ZeekReader
from app.engines.packet_intelligence.zeek import ZeekRunnerResult, ZeekRunnerStatus


class TestTLSAdapter(unittest.TestCase):
    """Unit tests for TLSAdapter mapping boundary."""

    def setUp(self):
        self.adapter = TLSAdapter()
        self.acq_id = "test-acq-tls"
        self.flow_index = {"T123": "flow-tls-001"}
        
        self.base_record = {
            "ts": 1700000010.0,
            "uid": "T123",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49392,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 443,
            "version": "TLSv1.2",
            "cipher": "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "server_name": "example.com",
            "resumed": False,
            "established": True,
            "subject": "CN=example.com",
            "issuer": "CN=Test CA",
            "validation_status": "ok"
        }

    def _make_raw(self, record_dict: dict, log_type: str = "ssl") -> RawZeekRecord:
        return RawZeekRecord(
            acquisition_id=self.acq_id,
            source_log=f"{log_type}.log",
            log_type=log_type,
            record=record_dict,
            line_number=1,
        )

    def test_valid_tls_12_record(self):
        """Test valid TLS 1.2 record mapping."""
        raw = self._make_raw(self.base_record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertIsNotNone(result.event_id)
        self.assertEqual(result.flow_id, "flow-tls-001")
        self.assertEqual(result.zeek_uid, "T123")
        self.assertEqual(result.protocol, "tls")
        
        data = result.protocol_data
        self.assertIsInstance(data, TLSData)
        self.assertEqual(data.version, "TLSv1.2")
        self.assertEqual(data.cipher, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        self.assertEqual(data.server_name, "example.com")
        self.assertEqual(data.subject, "CN=example.com")
        self.assertEqual(data.issuer, "CN=Test CA")

    def test_valid_tls_13_record(self):
        """Test valid TLS 1.3 record mapping."""
        record = self.base_record.copy()
        record["version"] = "TLSv1.3"
        record["cipher"] = "TLS_AES_128_GCM_SHA256"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertEqual(result.protocol_data.version, "TLSv1.3")
        self.assertEqual(result.protocol_data.cipher, "TLS_AES_128_GCM_SHA256")

    def test_missing_server_name(self):
        """Test missing SNI maps to None (common in encrypted ClientHello or older TLS)."""
        record = self.base_record.copy()
        record["server_name"] = "-"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertIsNone(result.protocol_data.server_name)

    def test_missing_cipher(self):
        """Test missing cipher maps to None."""
        record = self.base_record.copy()
        record["cipher"] = "-"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertIsNone(result.protocol_data.cipher)

    def test_missing_uid(self):
        """Test missing uid fails with MISSING_REQUIRED_FIELD."""
        record = self.base_record.copy()
        del record["uid"]
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, AdapterError)
        self.assertEqual(result.code, AdapterErrorCode.MISSING_REQUIRED_FIELD)

    def test_unknown_uid_orphan_event(self):
        """MANDATORY: Verify unknown uid does not create a fake flow."""
        record = self.base_record.copy()
        record["uid"] = "UNKNOWN_UID_XYZ"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, AdapterError)
        self.assertEqual(result.code, AdapterErrorCode.UNKNOWN_UID)

    def test_join_logic(self):
        """MANDATORY: Verify ProtocolEvent.flow_id is resolved properly from index."""
        record = self.base_record.copy()
        record["uid"] = "T789"
        
        custom_index = {"T789": "flow-xyz-888"}
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, custom_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertEqual(result.flow_id, "flow-xyz-888")
        self.assertEqual(result.zeek_uid, "T789")

    def test_invalid_timestamp(self):
        """Test invalid timestamp fails with INVALID_TYPE."""
        record = self.base_record.copy()
        record["ts"] = "not_a_float"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, AdapterError)
        self.assertEqual(result.code, AdapterErrorCode.INVALID_TYPE)

    def test_wrong_log_type(self):
        """Test wrong log type (conn.log) fails with UNSUPPORTED_LOG_TYPE."""
        raw = self._make_raw(self.base_record, log_type="conn")
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, AdapterError)
        self.assertEqual(result.code, AdapterErrorCode.UNSUPPORTED_LOG_TYPE)

    def test_provenance_preservation(self):
        """Test identities and provenance are fully preserved."""
        raw = self._make_raw(self.base_record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertEqual(result.acquisition_id, self.acq_id)
        self.assertIsNone(result.evidence_id)
        
        prov = result.provenance
        self.assertEqual(prov.acquisition_id, self.acq_id)
        self.assertEqual(prov.zeek_uid, "T123")
        self.assertEqual(prov.source, "zeek")
        self.assertEqual(prov.source_log, "ssl.log")
        self.assertIsNotNone(prov.processed_at)

    def test_encryption_boundary_compliance(self):
        """MANDATORY: Asserts no HTTP fields are synthesized from TLS data."""
        raw = self._make_raw(self.base_record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        # Ensure we didn't accidentally produce HTTPData
        self.assertIsInstance(result.protocol_data, TLSData)
        # Verify TLSData schema does NOT have HTTP fields
        with self.assertRaises(AttributeError):
            _ = result.protocol_data.uri
        with self.assertRaises(AttributeError):
            _ = result.protocol_data.method
        with self.assertRaises(AttributeError):
            _ = result.protocol_data.status_code


class TestTLSAdapterIntegration(unittest.TestCase):
    """Integration test: Reader -> ConnAdapter -> Index -> TLSAdapter -> ProtocolEvent."""

    def setUp(self):
        self.output_root_temp = tempfile.mkdtemp()
        self.output_dir = Path(self.output_root_temp)
        self.reader = ZeekReader()
        self.conn_adapter = ConnAdapter()
        self.tls_adapter = TLSAdapter()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.output_root_temp, ignore_errors=True)

    def test_integration_pipeline_to_tls_event(self):
        """End-to-End: JSON Logs -> Reader -> flow_index -> TLSAdapter -> ProtocolEvent."""
        # 1. Create mock conn.log and ssl.log
        conn_log_content = (
            '{"ts":1700000000.0,"uid":"T456","id.orig_h":"192.168.1.1","id.orig_p":1234,"id.resp_h":"1.1.1.1","id.resp_p":443,"proto":"tcp","service":"ssl","duration":0.01,"orig_bytes":150,"resp_bytes":550,"conn_state":"SF"}\n'
        )
        ssl_log_content = (
            '{"ts":1700000000.1,"uid":"T456","id.orig_h":"192.168.1.1","id.orig_p":1234,"id.resp_h":"1.1.1.1","id.resp_p":443,"version":"TLSv1.3","cipher":"TLS_AES_128_GCM_SHA256","server_name":"api.example.com","resumed":false,"established":true}\n'
        )
        
        (self.output_dir / "conn.log").write_text(conn_log_content, encoding="utf-8")
        (self.output_dir / "ssl.log").write_text(ssl_log_content, encoding="utf-8")

        # 2. Mock Phase 3 result
        runner_result = ZeekRunnerResult(
            acquisition_id="acq-int-tls",
            status=ZeekRunnerStatus.SUCCESS,
            output_directory=self.output_dir,
            generated_logs=["conn.log", "ssl.log"],
            exit_code=0,
            execution_duration_s=1.0,
            zeek_image="zeek/zeek:lts",
            zeek_version="8.0.0",
            stderr_tail="",
        )

        # 3. Stream conn.log to build flow_index
        flow_index = {}
        for raw_record in self.reader.read(runner_result):
            if isinstance(raw_record, RawZeekRecord) and raw_record.log_type == "conn":
                flow_result = self.conn_adapter.convert(raw_record)
                if isinstance(flow_result, Flow):
                    flow_index[flow_result.zeek_uid] = flow_result.flow_id

        self.assertIn("T456", flow_index)

        # 4. Stream ssl.log to build ProtocolEvents using flow_index
        events = []
        errors = []
        for raw_record in self.reader.read(runner_result):
            if isinstance(raw_record, RawZeekRecord) and raw_record.log_type == "ssl":
                event_result = self.tls_adapter.convert(raw_record, flow_index)
                if isinstance(event_result, ProtocolEvent):
                    events.append(event_result)
                else:
                    errors.append(event_result)

        self.assertEqual(len(events), 1, "Expected exactly one ProtocolEvent")
        self.assertEqual(len(errors), 0, f"Did not expect mapping errors: {errors}")

        event = events[0]
        self.assertIsInstance(event, ProtocolEvent)
        self.assertEqual(event.acquisition_id, "acq-int-tls")
        self.assertEqual(event.flow_id, flow_index["T456"])
        self.assertEqual(event.zeek_uid, "T456")
        self.assertEqual(event.protocol, "tls")
        
        data = event.protocol_data
        self.assertIsInstance(data, TLSData)
        self.assertEqual(data.version, "TLSv1.3")
        self.assertEqual(data.cipher, "TLS_AES_128_GCM_SHA256")
        self.assertEqual(data.server_name, "api.example.com")


if __name__ == "__main__":
    unittest.main()
