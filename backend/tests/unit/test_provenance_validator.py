"""
backend/tests/unit/test_provenance_validator.py
-----------------------------------------------
Unit tests for the Phase 9 Provenance Validator.
"""

from __future__ import annotations

import unittest
from datetime import datetime, timezone

from backend.app.contracts.network_intelligence import (
    Artifact,
    ArtifactProvenance,
    ArtifactType,
    DNSData,
    EventProvenance,
    ProtocolEvent,
)
from backend.app.engines.packet_intelligence.provenance import (
    ProvenanceError,
    ProvenanceErrorCode,
    ProvenanceValidator,
)


class TestProvenanceValidator(unittest.TestCase):
    """Unit tests for ProvenanceValidator boundary constraints."""

    def setUp(self):
        self.validator = ProvenanceValidator()

        self.event = ProtocolEvent(
            event_id="evt-001",
            flow_id="flow-001",
            zeek_uid="Z123",
            acquisition_id="acq-001",
            evidence_id="ev-001",
            timestamp=datetime.now(timezone.utc),
            protocol="dns",
            protocol_data=DNSData(query="example.com"),
            provenance=EventProvenance(
                acquisition_id="acq-001",
                source="zeek",
                source_log="dns.log",
            ),
        )

        self.base_artifact_kwargs = {
            "artifact_id": "art-001",
            "type": ArtifactType.DOMAIN,
            "value": "example.com",
            "source_event_id": "evt-001",
            "flow_id": "flow-001",
            "acquisition_id": "acq-001",
            "evidence_id": "ev-001",
            "first_seen": self.event.timestamp,
            "last_seen": self.event.timestamp,
            "provenance": ArtifactProvenance(
                acquisition_id="acq-001",
                evidence_id="ev-001",
                source_event_id="evt-001",
                derived_from="extracted",
            ),
        }

    def test_valid_provenance_succeeds(self):
        """MANDATORY: Verify valid provenance succeeds silently."""
        artifact = Artifact(**self.base_artifact_kwargs)
        try:
            self.validator.validate_artifact_provenance(artifact, self.event)
        except ProvenanceError:
            self.fail("validate_artifact_provenance raised ProvenanceError unexpectedly!")

    def test_missing_source_event_id_raises_error(self):
        kwargs = self.base_artifact_kwargs.copy()
        kwargs["source_event_id"] = None
        artifact = Artifact(**kwargs)
        
        with self.assertRaises(ProvenanceError) as cm:
            self.validator.validate_artifact_provenance(artifact, self.event)
            
        self.assertEqual(cm.exception.code, ProvenanceErrorCode.MISSING_REQUIRED_REFERENCE)

    def test_mismatched_event_id_raises_error(self):
        kwargs = self.base_artifact_kwargs.copy()
        kwargs["source_event_id"] = "evt-999"
        artifact = Artifact(**kwargs)
        
        with self.assertRaises(ProvenanceError) as cm:
            self.validator.validate_artifact_provenance(artifact, self.event)
            
        self.assertEqual(cm.exception.code, ProvenanceErrorCode.MISMATCHED_EVENT_ID)

    def test_mismatched_flow_id_raises_error(self):
        """MANDATORY: Verify cross-flow linkage fails."""
        kwargs = self.base_artifact_kwargs.copy()
        kwargs["flow_id"] = "flow-999"
        artifact = Artifact(**kwargs)
        
        with self.assertRaises(ProvenanceError) as cm:
            self.validator.validate_artifact_provenance(artifact, self.event)
            
        self.assertEqual(cm.exception.code, ProvenanceErrorCode.MISMATCHED_FLOW_ID)

    def test_mismatched_acquisition_id_raises_error(self):
        kwargs = self.base_artifact_kwargs.copy()
        kwargs["acquisition_id"] = "acq-999"
        artifact = Artifact(**kwargs)
        
        with self.assertRaises(ProvenanceError) as cm:
            self.validator.validate_artifact_provenance(artifact, self.event)
            
        self.assertEqual(cm.exception.code, ProvenanceErrorCode.MISMATCHED_ACQUISITION_ID)


if __name__ == "__main__":
    unittest.main()
