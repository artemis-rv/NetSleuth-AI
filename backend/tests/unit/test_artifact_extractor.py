"""
backend/tests/unit/test_artifact_extractor.py
---------------------------------------------
Unit tests for the Phase 9 Artifact Extractor.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from app.contracts.network_intelligence import (
    ArtifactType,
    DNSData,
    EventProvenance,
    HTTPData,
    ProtocolEvent,
    TLSData,
)
from app.engines.packet_intelligence.artifacts import ArtifactExtractor


class TestArtifactExtractor(unittest.TestCase):
    """Unit tests for ArtifactExtractor boundary mapping."""

    def setUp(self):
        self.extractor = ArtifactExtractor()
        
        self.prov = EventProvenance(
            acquisition_id="acq-999",
            evidence_id="ev-999",
            zeek_uid="Z123",
            source="zeek",
            source_log="test.log",
            processed_at=datetime.now(timezone.utc),
        )

        self.base_event_kwargs = {
            "event_id": "evt-001",
            "flow_id": "flow-001",
            "zeek_uid": "Z123",
            "acquisition_id": "acq-999",
            "evidence_id": "ev-999",
            "timestamp": datetime.now(timezone.utc),
            "provenance": self.prov,
        }

    def test_dns_query_extracts_domain(self):
        event = ProtocolEvent(
            **self.base_event_kwargs,
            protocol="dns",
            protocol_data=DNSData(query="example.com", answers=[]),
        )
        artifacts = self.extractor.extract(event)
        
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].type, ArtifactType.DOMAIN)
        self.assertEqual(artifacts[0].value, "example.com")

    def test_dns_answer_extracts_ip_and_domain(self):
        event = ProtocolEvent(
            **self.base_event_kwargs,
            protocol="dns",
            protocol_data=DNSData(
                query="example.com", 
                answers=["192.168.1.1", "2001:db8::1", "cname.example.com"]
            ),
        )
        artifacts = self.extractor.extract(event)
        
        self.assertEqual(len(artifacts), 4)
        types = [a.type for a in artifacts]
        values = [a.value for a in artifacts]
        
        self.assertEqual(types.count(ArtifactType.DOMAIN), 2)
        self.assertEqual(types.count(ArtifactType.IP), 2)
        self.assertIn("example.com", values)
        self.assertIn("192.168.1.1", values)
        self.assertIn("2001:db8::1", values)
        self.assertIn("cname.example.com", values)

    def test_http_extracts_host_and_user_agent(self):
        event = ProtocolEvent(
            **self.base_event_kwargs,
            protocol="http",
            protocol_data=HTTPData(
                host="api.example.com",
                user_agent="Mozilla/5.0",
                method="GET",
                uri="/test"
            ),
        )
        artifacts = self.extractor.extract(event)
        
        self.assertEqual(len(artifacts), 2)
        types = [a.type for a in artifacts]
        
        self.assertIn(ArtifactType.DOMAIN, types)
        self.assertIn(ArtifactType.USER_AGENT, types)
        
        for a in artifacts:
            if a.type == ArtifactType.DOMAIN:
                self.assertEqual(a.value, "api.example.com")
            else:
                self.assertEqual(a.value, "Mozilla/5.0")

    def test_tls_extracts_sni(self):
        event = ProtocolEvent(
            **self.base_event_kwargs,
            protocol="tls",
            protocol_data=TLSData(
                server_name="secure.example.com",
                subject="CN=secure.example.com",
            ),
        )
        artifacts = self.extractor.extract(event)
        
        self.assertEqual(len(artifacts), 1)
        self.assertEqual(artifacts[0].type, ArtifactType.DOMAIN)
        self.assertEqual(artifacts[0].value, "secure.example.com")

    def test_missing_fields_do_not_produce_artifacts(self):
        event = ProtocolEvent(
            **self.base_event_kwargs,
            protocol="http",
            protocol_data=HTTPData(
                host=None,
                user_agent=None,
            ),
        )
        artifacts = self.extractor.extract(event)
        self.assertEqual(len(artifacts), 0)

    def test_provenance_fields_preserved(self):
        """MANDATORY: Verify all provenance links map correctly."""
        event = ProtocolEvent(
            **self.base_event_kwargs,
            protocol="dns",
            protocol_data=DNSData(query="example.com", answers=[]),
        )
        artifact = self.extractor.extract(event)[0]
        
        self.assertEqual(artifact.source_event_id, "evt-001")
        self.assertEqual(artifact.flow_id, "flow-001")
        self.assertEqual(artifact.acquisition_id, "acq-999")
        self.assertEqual(artifact.evidence_id, "ev-999")
        self.assertEqual(artifact.first_seen, event.timestamp)
        self.assertEqual(artifact.last_seen, event.timestamp)
        
        prov = artifact.provenance
        self.assertEqual(prov.source_event_id, "evt-001")
        self.assertEqual(prov.acquisition_id, "acq-999")
        self.assertEqual(prov.derived_from, "extracted from protocol data")

    def test_duplicate_observations_preserve_separate_provenance(self):
        """MANDATORY: Duplicate observations do not implicitly deduplicate here."""
        event1 = ProtocolEvent(
            **self.base_event_kwargs,
            protocol="dns",
            protocol_data=DNSData(query="example.com", answers=[]),
        )
        
        event2_kwargs = self.base_event_kwargs.copy()
        event2_kwargs["event_id"] = "evt-002"
        event2 = ProtocolEvent(
            **event2_kwargs,
            protocol="http",
            protocol_data=HTTPData(host="example.com"),
        )
        
        artifacts1 = self.extractor.extract(event1)
        artifacts2 = self.extractor.extract(event2)
        
        self.assertEqual(len(artifacts1), 1)
        self.assertEqual(len(artifacts2), 1)
        self.assertEqual(artifacts1[0].value, "example.com")
        self.assertEqual(artifacts2[0].value, "example.com")
        self.assertEqual(artifacts1[0].source_event_id, "evt-001")
        self.assertEqual(artifacts2[0].source_event_id, "evt-002")

    def test_unsupported_protocol_data_returns_empty(self):
        event = ProtocolEvent(
            **self.base_event_kwargs,
            protocol="unknown",
            protocol_data={"unsupported": "data"},
        )
        artifacts = self.extractor.extract(event)
        self.assertEqual(len(artifacts), 0)


if __name__ == "__main__":
    unittest.main()
