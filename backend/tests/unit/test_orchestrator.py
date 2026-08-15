"""
backend/tests/unit/test_orchestrator.py
---------------------------------------
Unit and E2E Integration tests for M1Orchestrator.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from backend.app.contracts.network_intelligence import (
    AcquisitionReference,
    Artifact,
    ArtifactType,
    DNSData,
    EventProvenance,
    Flow,
    NetworkIntelligencePackage,
    ProtocolEvent,
    Provenance,
)
from backend.app.engines.packet_intelligence.adapters.conn import ConnAdapter
from backend.app.engines.packet_intelligence.adapters.dns import DNSAdapter
from backend.app.engines.packet_intelligence.adapters.http import HTTPAdapter
from backend.app.engines.packet_intelligence.adapters.tls import TLSAdapter
from backend.app.engines.packet_intelligence.artifacts.extractor import ArtifactExtractor
from backend.app.engines.packet_intelligence.errors import PackageAssemblyError, PackageAssemblyErrorCode
from backend.app.engines.packet_intelligence.orchestrator import M1Orchestrator
from backend.app.engines.packet_intelligence.provenance.validator import ProvenanceValidator
from backend.app.engines.packet_intelligence.zeek.reader import ZeekReader
from backend.app.engines.packet_intelligence.zeek.runner import ZeekRunner


class TestM1Orchestrator(unittest.TestCase):
    """Unit tests for M1Orchestrator relational integrity checks."""

    def setUp(self):
        self.runner_mock = MagicMock(spec=ZeekRunner)
        self.reader_mock = MagicMock(spec=ZeekReader)
        self.conn_mock = MagicMock(spec=ConnAdapter)
        self.dns_mock = MagicMock(spec=DNSAdapter)
        self.http_mock = MagicMock(spec=HTTPAdapter)
        self.tls_mock = MagicMock(spec=TLSAdapter)
        self.artifact_mock = MagicMock(spec=ArtifactExtractor)
        self.provenance_mock = MagicMock(spec=ProvenanceValidator)
        
        self.orchestrator = M1Orchestrator(
            zeek_runner=self.runner_mock,
            zeek_reader=self.reader_mock,
            conn_adapter=self.conn_mock,
            dns_adapter=self.dns_mock,
            http_adapter=self.http_mock,
            tls_adapter=self.tls_mock,
            artifact_extractor=self.artifact_mock,
            provenance_validator=self.provenance_mock,
        )

        self.acquisition = AcquisitionReference(
            acquisition_id="acq-111",
            evidence_id="ev-111",
            file_name="test.pcap",
            file_size=1024,
            format="pcap",
            sha256="deadbeef",
            capture_reference="/tmp/test.pcap",
            acquired_at=datetime.now(timezone.utc),
        )

    def _make_flow(self, flow_id="flow-001", acq_id="acq-111"):
        flow = MagicMock(spec=Flow)
        flow.flow_id = flow_id
        flow.zeek_uid = "Z123"
        flow.acquisition_id = acq_id
        return flow

    def _make_event(self, event_id="evt-001", flow_id="flow-001", acq_id="acq-111"):
        evt = MagicMock(spec=ProtocolEvent)
        evt.event_id = event_id
        evt.flow_id = flow_id
        evt.acquisition_id = acq_id
        return evt

    def _make_artifact(self, art_id="art-001", event_id="evt-001", flow_id="flow-001", acq_id="acq-111"):
        art = MagicMock(spec=Artifact)
        art.artifact_id = art_id
        art.source_event_id = event_id
        art.flow_id = flow_id
        art.acquisition_id = acq_id
        return art

    def test_missing_flow_reference_fails(self):
        """MANDATORY: Verify event -> flow failure."""
        flow = self._make_flow("flow-001")
        event = self._make_event("evt-001", flow_id="flow-MISSING")
        
        # We manually construct a fake reader pipeline output to bypass the mocks.
        # However, for pure relational checks, we can mock the inner methods.
        # Actually it's easier to just mock the adapters yielding this data.
        
        # Let reader return 2 records: one conn, one dns.
        self.reader_mock.read.return_value = [
            MagicMock(log_type="conn"),
            MagicMock(log_type="dns")
        ]
        self.conn_mock.convert.return_value = flow
        self.dns_mock.convert.return_value = event
        self.artifact_mock.extract.return_value = []
        
        with self.assertRaises(PackageAssemblyError) as cm:
            self.orchestrator.process_acquisition(self.acquisition)
            
        self.assertEqual(cm.exception.code, PackageAssemblyErrorCode.BROKEN_FLOW_REFERENCE)

    def test_missing_event_reference_fails(self):
        """MANDATORY: Verify artifact -> event failure."""
        flow = self._make_flow("flow-001")
        event = self._make_event("evt-001", flow_id="flow-001")
        artifact = self._make_artifact("art-001", event_id="evt-MISSING", flow_id="flow-001")
        
        self.reader_mock.read.return_value = [
            MagicMock(log_type="conn"),
            MagicMock(log_type="dns")
        ]
        self.conn_mock.convert.return_value = flow
        self.dns_mock.convert.return_value = event
        self.artifact_mock.extract.return_value = [artifact]
        
        with self.assertRaises(PackageAssemblyError) as cm:
            self.orchestrator.process_acquisition(self.acquisition)
            
        self.assertEqual(cm.exception.code, PackageAssemblyErrorCode.BROKEN_EVENT_REFERENCE)

    def test_mismatched_acquisition_fails(self):
        """MANDATORY: Verify acquisition integrity."""
        flow = self._make_flow("flow-001", acq_id="acq-WRONG")
        
        self.reader_mock.read.return_value = [MagicMock(log_type="conn")]
        self.conn_mock.convert.return_value = flow
        
        with self.assertRaises(PackageAssemblyError) as cm:
            self.orchestrator.process_acquisition(self.acquisition)
            
        self.assertEqual(cm.exception.code, PackageAssemblyErrorCode.ACQUISITION_MISMATCH)


class TestM1OrchestratorE2E(unittest.TestCase):
    """Real E2E integration test for M1Orchestrator."""
    
    def test_integration_full_pipeline(self):
        # We test with the actual test.pcap in sample_data
        pcap_path = Path("sample_data/evidence/capture.pcap").resolve()
        
        # If it doesn't exist, we skip the E2E so we don't break unnecessarily,
        # but we expect it to exist as verified by previous steps.
        if not pcap_path.exists():
            self.skipTest(f"Missing {pcap_path}")
            
        acq = AcquisitionReference(
            acquisition_id="acq-test-001",
            evidence_id="ev-test-001",
            file_name=pcap_path.name,
            file_size=pcap_path.stat().st_size,
            format="pcap",
            sha256="fakehash",
            capture_reference=str(pcap_path),
            acquired_at=datetime.now(timezone.utc),
        )
        
        # Real components
        zeek_runner = ZeekRunner()
        zeek_reader = ZeekReader()
        conn_adapter = ConnAdapter()
        dns_adapter = DNSAdapter()
        http_adapter = HTTPAdapter()
        tls_adapter = TLSAdapter()
        artifact_extractor = ArtifactExtractor()
        provenance_validator = ProvenanceValidator()
        
        orchestrator = M1Orchestrator(
            zeek_runner,
            zeek_reader,
            conn_adapter,
            dns_adapter,
            http_adapter,
            tls_adapter,
            artifact_extractor,
            provenance_validator
        )
        
        package = orchestrator.process_acquisition(acq)
        
        self.assertIsInstance(package, NetworkIntelligencePackage)
        self.assertEqual(package.acquisition_id, "acq-test-001")
        
        # Basic validation that we collected data
        self.assertGreater(len(package.flows), 0)
        self.assertGreater(len(package.protocol_events), 0)
        
        # MANDATORY DOWNSTREAM BOUNDARY TEST:
        # Verify no downstream fields appear in the serialized output.
        serialized = package.model_dump_json()
        self.assertNotIn("malicious", serialized)
        self.assertNotIn("risk_score", serialized)
        self.assertNotIn("severity", serialized)
        self.assertNotIn("mitre", serialized)

if __name__ == "__main__":
    unittest.main()
