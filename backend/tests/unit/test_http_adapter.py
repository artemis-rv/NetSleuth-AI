"""
backend/tests/unit/test_http_adapter.py
---------------------------------------
Unit tests for the Phase 7 HTTPAdapter.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from app.contracts.network_intelligence import HTTPData, ProtocolEvent, Flow
from app.engines.packet_intelligence.adapters import AdapterError, AdapterErrorCode, HTTPAdapter, ConnAdapter
from app.engines.packet_intelligence.zeek.reader import RawZeekRecord, ZeekReader
from app.engines.packet_intelligence.zeek import ZeekRunnerResult, ZeekRunnerStatus


class TestHTTPAdapter(unittest.TestCase):
    """Unit tests for HTTPAdapter mapping boundary."""

    def setUp(self):
        self.adapter = HTTPAdapter()
        self.acq_id = "test-acq-http"
        self.flow_index = {"C123": "flow-001"}
        
        self.base_record = {
            "ts": 1700000005.0,
            "uid": "C123",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49392,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 80,
            "trans_depth": 1,
            "method": "GET",
            "host": "example.com",
            "uri": "/index.html",
            "user_agent": "Mozilla/5.0",
            "request_body_len": 0,
            "response_body_len": 1200,
            "status_code": 200,
            "status_msg": "OK",
            "tags": []
        }

    def _make_raw(self, record_dict: dict, log_type: str = "http") -> RawZeekRecord:
        return RawZeekRecord(
            acquisition_id=self.acq_id,
            source_log=f"{log_type}.log",
            log_type=log_type,
            record=record_dict,
            line_number=1,
        )

    def test_valid_get_request(self):
        """Test valid GET request mapping."""
        raw = self._make_raw(self.base_record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertIsNotNone(result.event_id)
        self.assertEqual(result.flow_id, "flow-001")
        self.assertEqual(result.zeek_uid, "C123")
        self.assertEqual(result.protocol, "http")
        
        data = result.protocol_data
        self.assertIsInstance(data, HTTPData)
        self.assertEqual(data.method, "GET")
        self.assertEqual(data.host, "example.com")
        self.assertEqual(data.uri, "/index.html")
        self.assertEqual(data.status_code, 200)
        self.assertEqual(data.user_agent, "Mozilla/5.0")
        self.assertEqual(data.request_body_len, 0)
        self.assertEqual(data.response_body_len, 1200)

    def test_valid_post_request(self):
        """Test valid POST request mapping."""
        record = self.base_record.copy()
        record["method"] = "POST"
        record["uri"] = "/login"
        record["request_body_len"] = 450
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertEqual(result.protocol_data.method, "POST")
        self.assertEqual(result.protocol_data.uri, "/login")
        self.assertEqual(result.protocol_data.request_body_len, 450)

    def test_redirect_status_code(self):
        """Test HTTP 301/302 response."""
        record = self.base_record.copy()
        record["status_code"] = 301
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertEqual(result.protocol_data.status_code, 301)

    def test_missing_user_agent(self):
        """Test missing user agent maps to None."""
        record = self.base_record.copy()
        record["user_agent"] = "-"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertIsNone(result.protocol_data.user_agent)

    def test_missing_host(self):
        """Test missing host maps to None."""
        record = self.base_record.copy()
        record["host"] = "-"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertIsNone(result.protocol_data.host)

    def test_missing_uri(self):
        """Test missing URI maps to None."""
        record = self.base_record.copy()
        record["uri"] = "-"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertIsNone(result.protocol_data.uri)

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
        record["uid"] = "C789"
        
        custom_index = {"C789": "flow-xyz-999"}
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, custom_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertEqual(result.flow_id, "flow-xyz-999")
        self.assertEqual(result.zeek_uid, "C789")

    def test_invalid_timestamp(self):
        """Test invalid timestamp fails with INVALID_TYPE."""
        record = self.base_record.copy()
        record["ts"] = "not_a_float"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, AdapterError)
        self.assertEqual(result.code, AdapterErrorCode.INVALID_TYPE)

    def test_invalid_status_code(self):
        """Test invalid status code fails with INVALID_TYPE."""
        record = self.base_record.copy()
        record["status_code"] = "twenty_hundred"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, AdapterError)
        self.assertEqual(result.code, AdapterErrorCode.INVALID_TYPE)

    def test_invalid_request_size(self):
        """Test invalid request size fails with INVALID_TYPE."""
        record = self.base_record.copy()
        record["request_body_len"] = "large"
        
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
        self.assertEqual(prov.zeek_uid, "C123")
        self.assertEqual(prov.source, "zeek")
        self.assertEqual(prov.source_log, "http.log")
        self.assertIsNotNone(prov.processed_at)


class TestHTTPAdapterIntegration(unittest.TestCase):
    """Integration test: Reader -> ConnAdapter -> Index -> HTTPAdapter -> ProtocolEvent."""

    def setUp(self):
        self.output_root_temp = tempfile.mkdtemp()
        self.output_dir = Path(self.output_root_temp)
        self.reader = ZeekReader()
        self.conn_adapter = ConnAdapter()
        self.http_adapter = HTTPAdapter()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.output_root_temp, ignore_errors=True)

    def test_integration_pipeline_to_http_event(self):
        """End-to-End: JSON Logs -> Reader -> flow_index -> HTTPAdapter -> ProtocolEvent."""
        # 1. Create mock conn.log and http.log
        conn_log_content = (
            '{"ts":1700000000.0,"uid":"C456","id.orig_h":"192.168.1.1","id.orig_p":1234,"id.resp_h":"1.1.1.1","id.resp_p":80,"proto":"tcp","service":"http","duration":0.01,"orig_bytes":150,"resp_bytes":550,"conn_state":"SF"}\n'
        )
        http_log_content = (
            '{"ts":1700000000.1,"uid":"C456","id.orig_h":"192.168.1.1","id.orig_p":1234,"id.resp_h":"1.1.1.1","id.resp_p":80,"trans_depth":1,"method":"GET","host":"api.example.com","uri":"/v1/status","user_agent":"TestClient/1.0","request_body_len":0,"response_body_len":45,"status_code":200,"status_msg":"OK","tags":[]}\n'
        )
        
        (self.output_dir / "conn.log").write_text(conn_log_content, encoding="utf-8")
        (self.output_dir / "http.log").write_text(http_log_content, encoding="utf-8")

        # 2. Mock Phase 3 result
        runner_result = ZeekRunnerResult(
            acquisition_id="acq-int-http",
            status=ZeekRunnerStatus.SUCCESS,
            output_directory=self.output_dir,
            generated_logs=["conn.log", "http.log"],
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

        self.assertIn("C456", flow_index)

        # 4. Stream http.log to build ProtocolEvents using flow_index
        events = []
        errors = []
        for raw_record in self.reader.read(runner_result):
            if isinstance(raw_record, RawZeekRecord) and raw_record.log_type == "http":
                event_result = self.http_adapter.convert(raw_record, flow_index)
                if isinstance(event_result, ProtocolEvent):
                    events.append(event_result)
                else:
                    errors.append(event_result)

        self.assertEqual(len(events), 1, "Expected exactly one ProtocolEvent")
        self.assertEqual(len(errors), 0, f"Did not expect mapping errors: {errors}")

        event = events[0]
        self.assertIsInstance(event, ProtocolEvent)
        self.assertEqual(event.acquisition_id, "acq-int-http")
        self.assertEqual(event.flow_id, flow_index["C456"])
        self.assertEqual(event.zeek_uid, "C456")
        self.assertEqual(event.protocol, "http")
        
        data = event.protocol_data
        self.assertIsInstance(data, HTTPData)
        self.assertEqual(data.method, "GET")
        self.assertEqual(data.host, "api.example.com")
        self.assertEqual(data.uri, "/v1/status")
        self.assertEqual(data.status_code, 200)
        self.assertEqual(data.user_agent, "TestClient/1.0")


if __name__ == "__main__":
    unittest.main()
