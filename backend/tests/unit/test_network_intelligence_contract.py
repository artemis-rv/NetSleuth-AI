"""
test_network_intelligence_contract.py
--------------------------------------
Phase 1 contract tests for M1 NetworkIntelligencePackage and all
canonical M1 V1 pydantic models.

Test categories per specification:
  1. valid input
  2. boundary case
  3. malformed input
  4. missing field
  5. empty input where applicable
  6. contract compliance
  7. deterministic output
  8. provenance preservation
  9. referential integrity where applicable

Run command (from repo root, inside WSL venv):
  python -m unittest discover -s backend/tests/unit -v

Or directly:
  python -m unittest backend.tests.unit.test_network_intelligence_contract -v
"""

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path

# Ensure the backend package root is importable when run from repo root
_REPO_ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(_REPO_ROOT / "backend"))

from pydantic import ValidationError

from app.contracts.network_intelligence import (
    CONTRACT_VERSION,
    AcquisitionReference,
    Artifact,
    ArtifactProvenance,
    ArtifactType,
    DNSData,
    Endpoint,
    EventProvenance,
    Flow,
    FlowProvenance,
    HTTPData,
    NetworkIntelligencePackage,
    PacketReference,
    Protocol,
    ProtocolEvent,
    Provenance,
    TLSData,
)


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

_TS = datetime(2026, 8, 15, 10, 0, 0, tzinfo=timezone.utc)

_FLOW_PROV = FlowProvenance(
    acquisition_id="ACQ-001",
    evidence_id="EV-001",
    zeek_uid="Cabc123",
    source="zeek",
    source_log="conn.log",
)

_EVT_PROV = EventProvenance(
    acquisition_id="ACQ-001",
    evidence_id="EV-001",
    zeek_uid="Cabc123",
    source="zeek",
    source_log="dns.log",
)

_ART_PROV = ArtifactProvenance(
    acquisition_id="ACQ-001",
    evidence_id="EV-001",
    source_event_id="EVT-001",
)


def _make_endpoint(ip="10.0.0.1", port=12345) -> Endpoint:
    return Endpoint(ip=ip, port=port)


def _make_flow(flow_id="FLOW-001", zeek_uid="Cabc123") -> Flow:
    return Flow(
        flow_id=flow_id,
        zeek_uid=zeek_uid,
        acquisition_id="ACQ-001",
        timestamp=_TS,
        source=_make_endpoint("10.0.0.10", 52341),
        destination=_make_endpoint("203.0.113.10", 443),
        protocol="tcp",
        provenance=_FLOW_PROV,
    )


def _make_dns_event(event_id="EVT-001") -> ProtocolEvent:
    return ProtocolEvent(
        event_id=event_id,
        flow_id="FLOW-001",
        zeek_uid="Cabc123",
        acquisition_id="ACQ-001",
        timestamp=_TS,
        protocol="dns",
        protocol_data=DNSData(
            query="example.com",
            query_type="A",
            answers=["1.2.3.4"],
            response_code="NOERROR",
        ),
        provenance=_EVT_PROV,
    )


def _make_artifact(artifact_id="ART-001") -> Artifact:
    return Artifact(
        artifact_id=artifact_id,
        type=ArtifactType.DOMAIN,
        value="example.com",
        source_event_id="EVT-001",
        flow_id="FLOW-001",
        acquisition_id="ACQ-001",
        provenance=_ART_PROV,
    )


# ---------------------------------------------------------------------------
# ENDPOINT TESTS
# ---------------------------------------------------------------------------


class TestEndpoint(unittest.TestCase):
    def test_valid_endpoint(self):
        e = Endpoint(ip="10.0.0.1", port=443)
        self.assertEqual(e.ip, "10.0.0.1")
        self.assertEqual(e.port, 443)

    def test_port_boundary_zero(self):
        e = Endpoint(ip="0.0.0.0", port=0)
        self.assertEqual(e.port, 0)

    def test_port_boundary_max(self):
        e = Endpoint(ip="255.255.255.255", port=65535)
        self.assertEqual(e.port, 65535)

    def test_port_negative_rejected(self):
        with self.assertRaises(ValidationError):
            Endpoint(ip="10.0.0.1", port=-1)

    def test_port_over_max_rejected(self):
        with self.assertRaises(ValidationError):
            Endpoint(ip="10.0.0.1", port=65536)

    def test_missing_ip_rejected(self):
        with self.assertRaises(ValidationError):
            Endpoint(port=80)

    def test_missing_port_rejected(self):
        with self.assertRaises(ValidationError):
            Endpoint(ip="10.0.0.1")

    def test_frozen_immutable(self):
        e = Endpoint(ip="10.0.0.1", port=80)
        with self.assertRaises((ValidationError, TypeError)):
            e.port = 443  # type: ignore[misc]


# ---------------------------------------------------------------------------
# PROVENANCE TESTS
# ---------------------------------------------------------------------------


class TestFlowProvenance(unittest.TestCase):
    def test_valid_provenance(self):
        p = FlowProvenance(source="zeek", source_log="conn.log")
        self.assertEqual(p.source, "zeek")
        self.assertEqual(p.source_log, "conn.log")

    def test_optional_fields_default_none(self):
        p = FlowProvenance(source="zeek", source_log="conn.log")
        self.assertIsNone(p.acquisition_id)
        self.assertIsNone(p.evidence_id)
        self.assertIsNone(p.zeek_uid)

    def test_missing_source_rejected(self):
        with self.assertRaises(ValidationError):
            FlowProvenance(source_log="conn.log")

    def test_missing_source_log_rejected(self):
        with self.assertRaises(ValidationError):
            FlowProvenance(source="zeek")

    def test_full_provenance_preserved(self):
        p = FlowProvenance(
            acquisition_id="ACQ-001",
            evidence_id="EV-001",
            zeek_uid="Cabc",
            source="zeek",
            source_log="conn.log",
            processor_version="m1-v1.0",
        )
        self.assertEqual(p.acquisition_id, "ACQ-001")
        self.assertEqual(p.evidence_id, "EV-001")
        self.assertEqual(p.zeek_uid, "Cabc")
        self.assertEqual(p.processor_version, "m1-v1.0")


class TestEventProvenance(unittest.TestCase):
    def test_acquisition_id_required(self):
        with self.assertRaises(ValidationError):
            EventProvenance(source="zeek", source_log="dns.log")

    def test_valid_event_provenance(self):
        p = EventProvenance(
            acquisition_id="ACQ-001",
            source="zeek",
            source_log="dns.log",
        )
        self.assertEqual(p.acquisition_id, "ACQ-001")


# ---------------------------------------------------------------------------
# FLOW TESTS
# ---------------------------------------------------------------------------


class TestFlow(unittest.TestCase):
    def test_valid_minimal_flow(self):
        f = _make_flow()
        self.assertEqual(f.flow_id, "FLOW-001")
        self.assertEqual(f.zeek_uid, "Cabc123")
        self.assertEqual(f.object_type, "flow")

    def test_object_type_default_is_flow(self):
        f = _make_flow()
        self.assertEqual(f.object_type, "flow")

    def test_optional_fields_none(self):
        f = _make_flow()
        self.assertIsNone(f.duration)
        self.assertIsNone(f.orig_bytes)
        self.assertIsNone(f.resp_bytes)
        self.assertIsNone(f.connection_state)
        self.assertIsNone(f.service)
        self.assertIsNone(f.evidence_id)

    def test_full_flow_all_fields(self):
        f = Flow(
            flow_id="FLOW-002",
            zeek_uid="Cdef456",
            acquisition_id="ACQ-001",
            evidence_id="EV-001",
            timestamp=_TS,
            start_time=_TS,
            end_time=_TS,
            source=_make_endpoint("192.168.1.1", 1024),
            destination=_make_endpoint("8.8.8.8", 53),
            protocol="udp",
            service="dns",
            duration=0.001,
            orig_bytes=100,
            resp_bytes=200,
            orig_packets=1,
            resp_packets=1,
            connection_state="SF",
            provenance=_FLOW_PROV,
        )
        self.assertEqual(f.protocol, "udp")
        self.assertEqual(f.duration, 0.001)

    def test_missing_flow_id_rejected(self):
        with self.assertRaises(ValidationError):
            Flow(
                zeek_uid="Cabc",
                acquisition_id="ACQ-001",
                timestamp=_TS,
                source=_make_endpoint(),
                destination=_make_endpoint("1.2.3.4", 80),
                protocol="tcp",
                provenance=_FLOW_PROV,
            )

    def test_missing_provenance_rejected(self):
        with self.assertRaises(ValidationError):
            Flow(
                flow_id="FLOW-X",
                zeek_uid="Cabc",
                acquisition_id="ACQ-001",
                timestamp=_TS,
                source=_make_endpoint(),
                destination=_make_endpoint("1.2.3.4", 80),
                protocol="tcp",
            )

    def test_negative_duration_rejected(self):
        with self.assertRaises(ValidationError):
            Flow(
                flow_id="FLOW-X",
                zeek_uid="Cabc",
                acquisition_id="ACQ-001",
                timestamp=_TS,
                source=_make_endpoint(),
                destination=_make_endpoint("1.2.3.4", 80),
                protocol="tcp",
                duration=-1.0,
                provenance=_FLOW_PROV,
            )

    def test_frozen_immutable(self):
        f = _make_flow()
        with self.assertRaises((ValidationError, TypeError)):
            f.flow_id = "MODIFIED"  # type: ignore[misc]

    def test_provenance_acquisition_id_preserved(self):
        f = _make_flow()
        self.assertEqual(f.provenance.acquisition_id, "ACQ-001")

    def test_provenance_source_log_preserved(self):
        f = _make_flow()
        self.assertEqual(f.provenance.source_log, "conn.log")

    def test_zeek_uid_preserved(self):
        f = _make_flow(zeek_uid="CmyTestUID")
        self.assertEqual(f.zeek_uid, "CmyTestUID")


# ---------------------------------------------------------------------------
# PROTOCOL DATA TESTS
# ---------------------------------------------------------------------------


class TestDNSData(unittest.TestCase):
    def test_valid_dns_data(self):
        d = DNSData(
            query="example.com", query_type="A", answers=["1.2.3.4"], response_code="NOERROR"
        )
        self.assertEqual(d.query, "example.com")
        self.assertEqual(d.answers, ["1.2.3.4"])

    def test_empty_answers_list(self):
        d = DNSData(query="nxdomain.example", query_type="A", response_code="NXDOMAIN")
        self.assertEqual(d.answers, [])

    def test_multiple_answers(self):
        d = DNSData(answers=["1.1.1.1", "2.2.2.2", "3.3.3.3"])
        self.assertEqual(len(d.answers), 3)

    def test_all_fields_optional(self):
        d = DNSData()
        self.assertIsNone(d.query)
        self.assertIsNone(d.query_type)
        self.assertIsNone(d.response_code)
        self.assertEqual(d.answers, [])


class TestHTTPData(unittest.TestCase):
    def test_valid_http_data(self):
        d = HTTPData(method="GET", host="example.com", uri="/index.html", status_code=200)
        self.assertEqual(d.method, "GET")
        self.assertEqual(d.status_code, 200)

    def test_all_fields_optional(self):
        d = HTTPData()
        self.assertIsNone(d.method)
        self.assertIsNone(d.uri)

    def test_user_agent_preserved(self):
        ua = "Mozilla/5.0 (X11; Linux x86_64)"
        d = HTTPData(user_agent=ua)
        self.assertEqual(d.user_agent, ua)


class TestTLSData(unittest.TestCase):
    def test_valid_tls_data(self):
        d = TLSData(version="TLSv1.3", server_name="secure.example.com", cipher="TLS_AES_256_GCM_SHA384")
        self.assertEqual(d.version, "TLSv1.3")
        self.assertEqual(d.server_name, "secure.example.com")

    def test_all_fields_optional(self):
        d = TLSData()
        self.assertIsNone(d.version)
        self.assertIsNone(d.server_name)
        self.assertIsNone(d.cipher)


# ---------------------------------------------------------------------------
# PROTOCOL EVENT TESTS
# ---------------------------------------------------------------------------


class TestProtocolEvent(unittest.TestCase):
    def test_valid_dns_event(self):
        e = _make_dns_event()
        self.assertEqual(e.protocol, "dns")
        self.assertIsInstance(e.protocol_data, DNSData)

    def test_valid_http_event(self):
        e = ProtocolEvent(
            event_id="EVT-HTTP",
            flow_id="FLOW-001",
            zeek_uid="Cabc123",
            acquisition_id="ACQ-001",
            timestamp=_TS,
            protocol="http",
            protocol_data=HTTPData(method="GET", host="example.com", uri="/"),
            provenance=_EVT_PROV,
        )
        self.assertEqual(e.protocol, "http")

    def test_valid_tls_event(self):
        e = ProtocolEvent(
            event_id="EVT-TLS",
            flow_id="FLOW-001",
            zeek_uid="Cabc123",
            acquisition_id="ACQ-001",
            timestamp=_TS,
            protocol="tls",
            protocol_data=TLSData(server_name="example.com"),
            provenance=EventProvenance(
                acquisition_id="ACQ-001",
                source="zeek",
                source_log="ssl.log",
            ),
        )
        self.assertEqual(e.protocol_data.server_name, "example.com")

    def test_dict_passthrough_protocol_data(self):
        """Unexpected Zeek fields must not break the contract (pass-through)."""
        e = ProtocolEvent(
            event_id="EVT-PASS",
            flow_id="FLOW-001",
            zeek_uid="Cabc123",
            acquisition_id="ACQ-001",
            timestamp=_TS,
            protocol="unknown",
            protocol_data={"raw_field": "raw_value"},
            provenance=_EVT_PROV,
        )
        self.assertIsInstance(e.protocol_data, dict)

    def test_missing_event_id_rejected(self):
        with self.assertRaises(ValidationError):
            ProtocolEvent(
                flow_id="FLOW-001",
                zeek_uid="Cabc",
                acquisition_id="ACQ-001",
                timestamp=_TS,
                protocol="dns",
                protocol_data=DNSData(),
                provenance=_EVT_PROV,
            )

    def test_provenance_preserved(self):
        e = _make_dns_event()
        self.assertEqual(e.provenance.source_log, "dns.log")
        self.assertEqual(e.provenance.acquisition_id, "ACQ-001")

    def test_zeek_uid_preserved(self):
        e = _make_dns_event()
        self.assertEqual(e.zeek_uid, "Cabc123")

    def test_flow_id_referential_integrity(self):
        """event.flow_id must match the expected flow_id."""
        e = _make_dns_event()
        self.assertEqual(e.flow_id, "FLOW-001")

    def test_frozen_immutable(self):
        e = _make_dns_event()
        with self.assertRaises((ValidationError, TypeError)):
            e.event_id = "MODIFIED"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ARTIFACT TESTS
# ---------------------------------------------------------------------------


class TestArtifact(unittest.TestCase):
    def test_valid_domain_artifact(self):
        a = _make_artifact()
        self.assertEqual(a.type, ArtifactType.DOMAIN)
        self.assertEqual(a.value, "example.com")

    def test_all_artifact_types(self):
        for art_type in ArtifactType:
            a = Artifact(
                artifact_id=f"ART-{art_type.value}",
                type=art_type,
                value="test-value",
                acquisition_id="ACQ-001",
                provenance=_ART_PROV,
            )
            self.assertEqual(a.type, art_type)

    def test_missing_artifact_id_rejected(self):
        with self.assertRaises(ValidationError):
            Artifact(
                type=ArtifactType.IP,
                value="1.2.3.4",
                acquisition_id="ACQ-001",
                provenance=_ART_PROV,
            )

    def test_missing_value_rejected(self):
        with self.assertRaises(ValidationError):
            Artifact(
                artifact_id="ART-X",
                type=ArtifactType.IP,
                acquisition_id="ACQ-001",
                provenance=_ART_PROV,
            )

    def test_invalid_artifact_type_rejected(self):
        with self.assertRaises(ValidationError):
            Artifact(
                artifact_id="ART-BAD",
                type="MALWARE_HASH",  # not in ArtifactType V1
                value="abc123",
                acquisition_id="ACQ-001",
                provenance=_ART_PROV,
            )

    def test_optional_fields_none(self):
        a = _make_artifact()
        self.assertIsNone(a.evidence_id)
        self.assertIsNone(a.first_seen)
        self.assertIsNone(a.last_seen)

    def test_provenance_acquisition_id_preserved(self):
        a = _make_artifact()
        self.assertEqual(a.provenance.acquisition_id, "ACQ-001")

    def test_frozen_immutable(self):
        a = _make_artifact()
        with self.assertRaises((ValidationError, TypeError)):
            a.value = "modified"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# ACQUISITION REFERENCE TESTS
# ---------------------------------------------------------------------------


class TestAcquisitionReference(unittest.TestCase):
    def _make(self, **overrides):
        defaults = dict(
            acquisition_id="ACQ-001",
            evidence_id="EV-001",
            file_name="sample.pcap",
            file_size=1048576,
            format="pcap",
            sha256="a" * 64,
            capture_reference="/mnt/e/sample_data/evidence/sample.pcap",
        )
        defaults.update(overrides)
        return AcquisitionReference(**defaults)

    def test_valid_acquisition_reference(self):
        a = self._make()
        self.assertEqual(a.acquisition_id, "ACQ-001")
        self.assertEqual(a.format, "pcap")
        self.assertEqual(len(a.sha256), 64)

    def test_zero_byte_file(self):
        """Zero-byte files are valid input (they will be rejected by the validator, not here)."""
        a = self._make(file_size=0)
        self.assertEqual(a.file_size, 0)

    def test_negative_file_size_rejected(self):
        with self.assertRaises(ValidationError):
            self._make(file_size=-1)

    def test_missing_acquisition_id_rejected(self):
        with self.assertRaises(ValidationError):
            AcquisitionReference(
                evidence_id="EV-001",
                file_name="sample.pcap",
                file_size=100,
                format="pcap",
                sha256="a" * 64,
                capture_reference="/tmp/sample.pcap",
            )

    def test_frozen_immutable(self):
        a = self._make()
        with self.assertRaises((ValidationError, TypeError)):
            a.sha256 = "b" * 64  # type: ignore[misc]


# ---------------------------------------------------------------------------
# PACKET REFERENCE TESTS
# ---------------------------------------------------------------------------


class TestPacketReference(unittest.TestCase):
    def test_all_fields_optional(self):
        p = PacketReference()
        self.assertIsNone(p.evidence_id)
        self.assertIsNone(p.packet_start)

    def test_valid_packet_reference(self):
        p = PacketReference(
            evidence_id="EV-001",
            acquisition_id="ACQ-001",
            packet_start=1,
            packet_end=100,
        )
        self.assertEqual(p.packet_start, 1)
        self.assertEqual(p.packet_end, 100)


# ---------------------------------------------------------------------------
# NETWORK INTELLIGENCE PACKAGE TESTS
# ---------------------------------------------------------------------------


class TestNetworkIntelligencePackage(unittest.TestCase):
    def test_valid_minimal_package(self):
        pkg = NetworkIntelligencePackage(
            package_id="PKG-001",
            acquisition_id="ACQ-001",
        )
        self.assertEqual(pkg.package_id, "PKG-001")
        self.assertEqual(pkg.contract_version, CONTRACT_VERSION)
        self.assertEqual(pkg.flows, [])
        self.assertEqual(pkg.protocol_events, [])
        self.assertEqual(pkg.artifacts, [])
        self.assertEqual(pkg.packet_references, [])

    def test_contract_version_default(self):
        pkg = NetworkIntelligencePackage(
            package_id="PKG-001",
            acquisition_id="ACQ-001",
        )
        self.assertEqual(pkg.contract_version, "1.0")

    def test_empty_collections(self):
        pkg = NetworkIntelligencePackage(package_id="PKG-EMPTY", acquisition_id="ACQ-001")
        self.assertEqual(len(pkg.flows), 0)
        self.assertEqual(len(pkg.protocol_events), 0)
        self.assertEqual(len(pkg.artifacts), 0)
        self.assertEqual(len(pkg.packet_references), 0)

    def test_missing_package_id_rejected(self):
        with self.assertRaises(ValidationError):
            NetworkIntelligencePackage(acquisition_id="ACQ-001")

    def test_missing_acquisition_id_rejected(self):
        with self.assertRaises(ValidationError):
            NetworkIntelligencePackage(package_id="PKG-001")

    def test_full_package_with_all_objects(self):
        flow = _make_flow()
        event = _make_dns_event()
        artifact = _make_artifact()
        ref = PacketReference(evidence_id="EV-001", packet_start=1, packet_end=10)

        pkg = NetworkIntelligencePackage(
            package_id="PKG-FULL",
            acquisition_id="ACQ-001",
            flows=[flow],
            protocol_events=[event],
            artifacts=[artifact],
            packet_references=[ref],
        )
        self.assertEqual(len(pkg.flows), 1)
        self.assertEqual(len(pkg.protocol_events), 1)
        self.assertEqual(len(pkg.artifacts), 1)
        self.assertEqual(len(pkg.packet_references), 1)

    def test_frozen_immutable(self):
        pkg = NetworkIntelligencePackage(package_id="PKG-001", acquisition_id="ACQ-001")
        with self.assertRaises((ValidationError, TypeError)):
            pkg.package_id = "MODIFIED"  # type: ignore[misc]

    def test_deterministic_output(self):
        """Same input produces same model output every time."""
        flow = _make_flow()
        pkg1 = NetworkIntelligencePackage(
            package_id="PKG-DET", acquisition_id="ACQ-001", flows=[flow]
        )
        pkg2 = NetworkIntelligencePackage(
            package_id="PKG-DET", acquisition_id="ACQ-001", flows=[flow]
        )
        self.assertEqual(pkg1.model_dump(), pkg2.model_dump())

    def test_referential_integrity_flow_event(self):
        """Events reference a flow_id that exists in the package."""
        flow = _make_flow(flow_id="FLOW-REF")
        event = ProtocolEvent(
            event_id="EVT-REF",
            flow_id="FLOW-REF",
            zeek_uid="Cabc123",
            acquisition_id="ACQ-001",
            timestamp=_TS,
            protocol="dns",
            protocol_data=DNSData(),
            provenance=_EVT_PROV,
        )
        pkg = NetworkIntelligencePackage(
            package_id="PKG-RI",
            acquisition_id="ACQ-001",
            flows=[flow],
            protocol_events=[event],
        )
        flow_ids = {f.flow_id for f in pkg.flows}
        for e in pkg.protocol_events:
            self.assertIn(e.flow_id, flow_ids, msg=f"event {e.event_id} references unknown flow_id")

    def test_referential_integrity_artifact_event(self):
        """Artifacts that reference source_event_id must point to an existing event."""
        event = _make_dns_event(event_id="EVT-ART")
        artifact = Artifact(
            artifact_id="ART-REF",
            type=ArtifactType.DOMAIN,
            value="example.com",
            source_event_id="EVT-ART",
            acquisition_id="ACQ-001",
            provenance=_ART_PROV,
        )
        pkg = NetworkIntelligencePackage(
            package_id="PKG-ART-RI",
            acquisition_id="ACQ-001",
            flows=[_make_flow()],
            protocol_events=[event],
            artifacts=[artifact],
        )
        event_ids = {e.event_id for e in pkg.protocol_events}
        for a in pkg.artifacts:
            if a.source_event_id:
                self.assertIn(
                    a.source_event_id,
                    event_ids,
                    msg=f"artifact {a.artifact_id} references unknown event_id",
                )

    def test_package_no_downstream_fields(self):
        """Package must NOT have detection/risk/severity/MITRE fields."""
        pkg = NetworkIntelligencePackage(package_id="PKG-001", acquisition_id="ACQ-001")
        data = pkg.model_dump()
        forbidden = {
            "malicious", "risk_score", "severity", "attack_type", "mitre",
            "detection", "alert", "score", "confidence",
        }
        for field in forbidden:
            self.assertNotIn(field, data, msg=f"Downstream field '{field}' found in package")

    def test_provenance_not_silently_dropped(self):
        """Provenance fields on nested objects must survive serialisation round-trip."""
        flow = _make_flow()
        data = flow.model_dump()
        prov = data["provenance"]
        self.assertEqual(prov["source"], "zeek")
        self.assertEqual(prov["source_log"], "conn.log")
        self.assertEqual(prov["acquisition_id"], "ACQ-001")
        self.assertEqual(prov["zeek_uid"], "Cabc123")


# ---------------------------------------------------------------------------
# CONTRACT COMPLIANCE — FIXTURE ROUND-TRIP
# ---------------------------------------------------------------------------


class TestFixtureRoundTrip(unittest.TestCase):
    """Load the Phase 1 fixture and validate it round-trips through pydantic."""

    def _fixture_path(self) -> Path:
        return (
            Path(__file__).resolve().parents[3]
            / "fixtures"
            / "network_intelligence"
            / "network-intelligence-v1-m1-phase1.json"
        )

    def test_fixture_file_exists(self):
        self.assertTrue(self._fixture_path().exists(), "Phase 1 fixture file not found")

    def test_fixture_parses_as_package(self):
        import json

        with open(self._fixture_path(), encoding="utf-8") as f:
            raw = json.load(f)

        pkg = NetworkIntelligencePackage.model_validate(raw)
        self.assertEqual(pkg.contract_version, "1.0")
        self.assertEqual(pkg.acquisition_id, "ACQ-001")

    def test_fixture_has_one_flow(self):
        import json

        with open(self._fixture_path(), encoding="utf-8") as f:
            raw = json.load(f)

        pkg = NetworkIntelligencePackage.model_validate(raw)
        self.assertEqual(len(pkg.flows), 1)

    def test_fixture_has_two_events(self):
        import json

        with open(self._fixture_path(), encoding="utf-8") as f:
            raw = json.load(f)

        pkg = NetworkIntelligencePackage.model_validate(raw)
        self.assertEqual(len(pkg.protocol_events), 2)

    def test_fixture_has_two_artifacts(self):
        import json

        with open(self._fixture_path(), encoding="utf-8") as f:
            raw = json.load(f)

        pkg = NetworkIntelligencePackage.model_validate(raw)
        self.assertEqual(len(pkg.artifacts), 2)

    def test_fixture_flow_provenance_preserved(self):
        import json

        with open(self._fixture_path(), encoding="utf-8") as f:
            raw = json.load(f)

        pkg = NetworkIntelligencePackage.model_validate(raw)
        flow = pkg.flows[0]
        self.assertEqual(flow.provenance.source, "zeek")
        self.assertEqual(flow.provenance.source_log, "conn.log")
        self.assertEqual(flow.zeek_uid, "C1xYz2abc123")

    def test_fixture_serialise_deserialise_round_trip(self):
        """model_dump -> model_validate must produce identical objects."""
        import json

        with open(self._fixture_path(), encoding="utf-8") as f:
            raw = json.load(f)

        pkg1 = NetworkIntelligencePackage.model_validate(raw)
        pkg2 = NetworkIntelligencePackage.model_validate(pkg1.model_dump())
        self.assertEqual(pkg1.model_dump(), pkg2.model_dump())


if __name__ == "__main__":
    unittest.main()
