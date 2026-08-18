"""
backend/tests/unit/test_dns_adapter.py
--------------------------------------
Unit tests for the Phase 6 DNSAdapter.
"""

from __future__ import annotations

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

from app.contracts.network_intelligence import DNSData, ProtocolEvent, Flow
from app.engines.packet_intelligence.adapters import AdapterError, AdapterErrorCode, DNSAdapter, ConnAdapter
from app.engines.packet_intelligence.zeek.reader import RawZeekRecord, ZeekReader
from app.engines.packet_intelligence.zeek import ZeekRunnerResult, ZeekRunnerStatus


class TestDNSAdapter(unittest.TestCase):
    """Unit tests for DNSAdapter mapping boundary."""

    def setUp(self):
        self.adapter = DNSAdapter()
        self.acq_id = "test-acq-dns"
        self.flow_index = {"C123": "flow-001"}
        
        self.base_record = {
            "ts": 1700000005.0,
            "uid": "C123",
            "id.orig_h": "192.168.1.100",
            "id.orig_p": 49392,
            "id.resp_h": "10.0.0.5",
            "id.resp_p": 53,
            "proto": "udp",
            "query": "example.com",
            "qtype_name": "A",
            "rcode_name": "NOERROR",
            "answers": ["93.184.216.34"],
        }

    def _make_raw(self, record_dict: dict, log_type: str = "dns") -> RawZeekRecord:
        return RawZeekRecord(
            acquisition_id=self.acq_id,
            source_log=f"{log_type}.log",
            log_type=log_type,
            record=record_dict,
            line_number=1,
        )

    def test_valid_a_query(self):
        """Test valid A query."""
        raw = self._make_raw(self.base_record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertIsNotNone(result.event_id)
        self.assertEqual(result.flow_id, "flow-001")
        self.assertEqual(result.zeek_uid, "C123")
        self.assertEqual(result.protocol, "dns")
        
        data = result.protocol_data
        self.assertIsInstance(data, DNSData)
        self.assertEqual(data.query, "example.com")
        self.assertEqual(data.query_type, "A")
        self.assertEqual(data.response_code, "NOERROR")
        self.assertEqual(data.answers, ["93.184.216.34"])

    def test_valid_aaaa_query(self):
        """Test valid AAAA query."""
        record = self.base_record.copy()
        record["query"] = "ipv6.google.com"
        record["qtype_name"] = "AAAA"
        record["answers"] = ["2001:4860:4860::8888"]
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertEqual(result.protocol_data.query_type, "AAAA")
        self.assertEqual(result.protocol_data.answers, ["2001:4860:4860::8888"])

    def test_valid_cname_query(self):
        """Test valid MX/TXT/CNAME style record."""
        record = self.base_record.copy()
        record["qtype_name"] = "CNAME"
        record["answers"] = ["alias.example.com"]
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertEqual(result.protocol_data.query_type, "CNAME")
        self.assertEqual(result.protocol_data.answers, ["alias.example.com"])

    def test_nxdomain(self):
        """Test NXDOMAIN response."""
        record = self.base_record.copy()
        record["rcode_name"] = "NXDOMAIN"
        record["answers"] = "-"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertEqual(result.protocol_data.response_code, "NXDOMAIN")
        self.assertEqual(result.protocol_data.answers, [])

    def test_missing_uid(self):
        """Test missing uid fails."""
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

    def test_missing_query(self):
        """Test missing query leaves it None."""
        record = self.base_record.copy()
        record["query"] = "-"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertIsNone(result.protocol_data.query)

    def test_invalid_timestamp(self):
        """Test invalid timestamp."""
        record = self.base_record.copy()
        record["ts"] = "not_a_float"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, AdapterError)
        self.assertEqual(result.code, AdapterErrorCode.INVALID_TYPE)

    def test_malformed_answers_string(self):
        """Test answers as comma-separated string."""
        record = self.base_record.copy()
        record["answers"] = "1.1.1.1,8.8.8.8"
        
        raw = self._make_raw(record)
        result = self.adapter.convert(raw, self.flow_index)

        self.assertIsInstance(result, ProtocolEvent)
        self.assertEqual(result.protocol_data.answers, ["1.1.1.1", "8.8.8.8"])

    def test_wrong_log_type(self):
        """Test wrong log type (conn.log)."""
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
        self.assertEqual(prov.source_log, "dns.log")
        self.assertIsNotNone(prov.processed_at)


class TestDNSAdapterIntegration(unittest.TestCase):
    """Integration test: Reader -> ConnAdapter -> Index -> DNSAdapter -> ProtocolEvent."""

    def setUp(self):
        self.output_root_temp = tempfile.mkdtemp()
        self.output_dir = Path(self.output_root_temp)
        self.reader = ZeekReader()
        self.conn_adapter = ConnAdapter()
        self.dns_adapter = DNSAdapter()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.output_root_temp, ignore_errors=True)

    def test_integration_pipeline_to_dns_event(self):
        """End-to-End: JSON Logs -> Reader -> flow_index -> DNSAdapter -> ProtocolEvent."""
        # 1. Create mock conn.log and dns.log
        conn_log_content = (
            '{"ts":1700000000.0,"uid":"C123","id.orig_h":"192.168.1.1","id.orig_p":1234,"id.resp_h":"1.1.1.1","id.resp_p":53,"proto":"udp","service":"dns","duration":0.01,"orig_bytes":50,"resp_bytes":50,"conn_state":"SF"}\n'
        )
        dns_log_content = (
            '{"ts":1700000000.1,"uid":"C123","id.orig_h":"192.168.1.1","id.orig_p":1234,"id.resp_h":"1.1.1.1","id.resp_p":53,"proto":"udp","query":"example.com","qtype_name":"A","rcode_name":"NOERROR","answers":["93.184.216.34"]}\n'
        )
        
        (self.output_dir / "conn.log").write_text(conn_log_content, encoding="utf-8")
        (self.output_dir / "dns.log").write_text(dns_log_content, encoding="utf-8")

        # 2. Mock Phase 3 result
        runner_result = ZeekRunnerResult(
            acquisition_id="acq-int-dns",
            status=ZeekRunnerStatus.SUCCESS,
            output_directory=self.output_dir,
            generated_logs=["conn.log", "dns.log"],
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

        self.assertIn("C123", flow_index)

        # 4. Stream dns.log to build ProtocolEvents using flow_index
        events = []
        errors = []
        for raw_record in self.reader.read(runner_result):
            if isinstance(raw_record, RawZeekRecord) and raw_record.log_type == "dns":
                event_result = self.dns_adapter.convert(raw_record, flow_index)
                if isinstance(event_result, ProtocolEvent):
                    events.append(event_result)
                else:
                    errors.append(event_result)

        self.assertEqual(len(events), 1, "Expected exactly one ProtocolEvent")
        self.assertEqual(len(errors), 0, "Did not expect mapping errors")

        event = events[0]
        self.assertIsInstance(event, ProtocolEvent)
        self.assertEqual(event.acquisition_id, "acq-int-dns")
        self.assertEqual(event.flow_id, flow_index["C123"])
        self.assertEqual(event.zeek_uid, "C123")
        self.assertEqual(event.protocol, "dns")
        self.assertIsInstance(event.protocol_data, DNSData)
        self.assertEqual(event.protocol_data.query, "example.com")


if __name__ == "__main__":
    unittest.main()
