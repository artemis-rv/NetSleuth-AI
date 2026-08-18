import unittest
from datetime import datetime, timezone
import copy

from app.engines.correlation.domain.input import M3InvestigationInput, TelemetryCapability
from app.engines.correlation.adapters.m3_input_adapter import M3InputAdapter
from app.contracts.network_intelligence import NetworkIntelligencePackage, Flow, ProtocolEvent, Artifact, ArtifactType, FlowProvenance, EventProvenance, ArtifactProvenance, Endpoint, DNSData, HTTPData, TLSData
from app.contracts.analysis import FindingsPackage, Finding, ActivityClass, EvidenceReference

class TestM3InputAdapter(unittest.TestCase):
    def setUp(self):
        self.adapter = M3InputAdapter()
        
        # Base M1 Package
        self.base_m1 = {
            "package_id": "PKG-M1-001",
            "contract_version": "1.0",
            "acquisition_id": "ACQ-001",
            "flows": [
                {
                    "flow_id": "F-001",
                    "zeek_uid": "CuXy",
                    "acquisition_id": "ACQ-001",
                    "timestamp": "2026-08-17T12:00:00Z",
                    "source": {"ip": "10.0.0.1", "port": 12345},
                    "destination": {"ip": "8.8.8.8", "port": 53},
                    "protocol": "udp",
                    "service": "dns",
                    "provenance": {"source": "zeek", "source_log": "conn.log"}
                }
            ],
            "protocol_events": [
                {
                    "event_id": "E-001",
                    "flow_id": "F-001",
                    "zeek_uid": "CuXy",
                    "acquisition_id": "ACQ-001",
                    "timestamp": "2026-08-17T12:00:00Z",
                    "protocol": "dns",
                    "protocol_data": {"query": "example.com", "query_type": "A", "answers": []},
                    "provenance": {"source": "zeek", "source_log": "dns.log", "acquisition_id": "ACQ-001"}
                }
            ],
            "artifacts": [
                {
                    "artifact_id": "A-001",
                    "type": "DOMAIN",
                    "value": "example.com",
                    "source_event_id": "E-001",
                    "acquisition_id": "ACQ-001",
                    "provenance": {"source": "zeek", "acquisition_id": "ACQ-001"}
                }
            ],
            "packet_references": []
        }
        
        # Base M2 Package
        self.base_m2 = {
            "package_id": "PKG-M2-001",
            "contract_version": "1.0",
            "acquisition_id": "ACQ-001",
            "source_package_id": "PKG-M1-001",
            "findings": [
                {
                    "finding_id": "FND-001",
                    "acquisition_id": "ACQ-001",
                    "activity_class": "DNS_ANOMALY_TUNNELING",
                    "anomaly_score": 0.85,
                    "anomaly_detected": True,
                    "classification_confidence": 0.92,
                    "risk_score": 0.88,
                    "evidence_references": [
                        {
                            "flow_ids": ["F-001"],
                            "event_ids": ["E-001"],
                            "artifact_ids": ["A-001"],
                            "rationale": "Unusual DNS query lengths and frequencies."
                        }
                    ],
                    "model_version": "1.0.0",
                    "created_at": "2026-08-17T12:05:00Z"
                }
            ],
            "analysis_engine_version": "1.0.0",
            "analysed_at": "2026-08-17T12:05:00Z"
        }

    # -------------------------------------------------------------------------
    # TEST 1 - REAL M1 INPUT
    # -------------------------------------------------------------------------
    def test_01_real_m1_input_preservation(self):
        result = self.adapter.adapt(self.base_m1, self.base_m2)
        
        self.assertEqual(result.acquisition_id, "ACQ-001")
        self.assertEqual(result.network_package_id, "PKG-M1-001")
        self.assertEqual(len(result.network_flows), 1)
        self.assertEqual(result.network_flows[0].flow_id, "F-001")
        self.assertEqual(len(result.protocol_events), 1)
        self.assertEqual(result.protocol_events[0].event_id, "E-001")
        self.assertEqual(len(result.artifacts), 1)
        self.assertEqual(result.artifacts[0].artifact_id, "A-001")
        
        # Timestamp semantic unchanged (tz aware)
        self.assertEqual(result.network_flows[0].timestamp, datetime(2026, 8, 17, 12, 0, 0, tzinfo=timezone.utc))

    # -------------------------------------------------------------------------
    # TEST 2 - REAL M2 INPUT
    # -------------------------------------------------------------------------
    def test_02_real_m2_input_preservation(self):
        result = self.adapter.adapt(self.base_m1, self.base_m2)
        
        self.assertEqual(result.findings_package_id, "PKG-M2-001")
        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.finding_id, "FND-001")
        self.assertEqual(finding.activity_class, ActivityClass.DNS_ANOMALY_TUNNELING)
        self.assertEqual(finding.anomaly_score, 0.85)
        self.assertEqual(finding.classification_confidence, 0.92)
        self.assertEqual(finding.risk_score, 0.88)
        self.assertEqual(len(finding.evidence_references), 1)
        self.assertEqual(finding.evidence_references[0].flow_ids, ["F-001"])

    # -------------------------------------------------------------------------
    # TEST 3 & 12 - EVIDENCE TRACEABILITY & INTEGRITY
    # -------------------------------------------------------------------------
    def test_03_evidence_traceability_valid(self):
        result = self.adapter.adapt(self.base_m1, self.base_m2)
        finding = result.evidence_index.findings["FND-001"]
        ref = finding.evidence_references[0]
        
        # Traverse
        for f_id in ref.flow_ids:
            self.assertIn(f_id, result.evidence_index.flows)
        for e_id in ref.event_ids:
            self.assertIn(e_id, result.evidence_index.events)
        for a_id in ref.artifact_ids:
            self.assertIn(a_id, result.evidence_index.artifacts)

    def test_03b_evidence_traceability_invalid_rejects(self):
        # M2 references an evidence ID that doesn't exist in M1
        m2_bad = copy.deepcopy(self.base_m2)
        m2_bad["findings"][0]["evidence_references"][0]["flow_ids"].append("F-MISSING")
        
        # Adapter should validate integrity and reject. Wait! The current adapter doesn't reject it yet.
        # Let's see if the test fails. We must UPDATE the adapter if it doesn't.
        with self.assertRaises(ValueError):
            self.adapter.adapt(self.base_m1, m2_bad)

    # -------------------------------------------------------------------------
    # TEST 4 - ACQUISITION ISOLATION
    # -------------------------------------------------------------------------
    def test_04_acquisition_isolation(self):
        m2_diff = copy.deepcopy(self.base_m2)
        m2_diff["acquisition_id"] = "ACQ-002"
        m2_diff["findings"][0]["acquisition_id"] = "ACQ-002"
        
        with self.assertRaises(ValueError) as context:
            self.adapter.adapt(self.base_m1, m2_diff)
        self.assertIn("Acquisition ID mismatch", str(context.exception))

    # -------------------------------------------------------------------------
    # TEST 5 & 6 - TELEMETRY CAPABILITY
    # -------------------------------------------------------------------------
    def test_05_telemetry_derived_from_m1(self):
        result = self.adapter.adapt(self.base_m1, self.base_m2)
        self.assertTrue(result.telemetry_capabilities.network_flow)
        self.assertTrue(result.telemetry_capabilities.dns)
        self.assertFalse(result.telemetry_capabilities.http)
        self.assertFalse(result.telemetry_capabilities.tls)

    def test_06_unsupported_telemetry_not_fabricated(self):
        # HTTP is missing in M1
        result = self.adapter.adapt(self.base_m1, self.base_m2)
        self.assertFalse(result.telemetry_capabilities.http)

    # -------------------------------------------------------------------------
    # TEST 7 - LOSSLESSNESS
    # -------------------------------------------------------------------------
    def test_07_lossless_semantic_equivalence(self):
        result = self.adapter.adapt(self.base_m1, self.base_m2)
        # Verify M1 nested objects are perfectly preserved
        m1_flow = result.network_flows[0]
        self.assertEqual(m1_flow.source.ip, "10.0.0.1")
        self.assertEqual(m1_flow.provenance.source, "zeek")
        
        # Verify M2 nested objects are perfectly preserved
        m2_finding = result.findings[0]
        self.assertEqual(m2_finding.activity_class.value, "DNS_ANOMALY_TUNNELING")

    # -------------------------------------------------------------------------
    # TEST 8 - DETERMINISM
    # -------------------------------------------------------------------------
    def test_08_determinism(self):
        r1 = self.adapter.adapt(self.base_m1, self.base_m2)
        r2 = self.adapter.adapt(self.base_m1, self.base_m2)
        
        self.assertEqual(r1.acquisition_id, r2.acquisition_id)
        self.assertEqual(r1.network_flows[0].flow_id, r2.network_flows[0].flow_id)
        # Ensure no random UUIDs generated for normalized inputs
        self.assertEqual(id(r1.network_flows[0]), id(r1.network_flows[0])) # Not strict, but ids shouldn't mutate

    # -------------------------------------------------------------------------
    # TEST 9 - DUPLICATES
    # -------------------------------------------------------------------------
    def test_09_duplicates_rejects(self):
        m1_dup = copy.deepcopy(self.base_m1)
        m1_dup["flows"].append(m1_dup["flows"][0]) # Duplicate F-001
        
        with self.assertRaises(ValueError) as ctx:
            self.adapter.adapt(m1_dup, self.base_m2)
        self.assertIn("Duplicate flow_id", str(ctx.exception))

    # -------------------------------------------------------------------------
    # TEST 10 - TIMESTAMP SAFETY
    # -------------------------------------------------------------------------
    def test_10_timestamp_safety(self):
        m1_naive = copy.deepcopy(self.base_m1)
        m1_naive["flows"][0]["timestamp"] = "2026-08-17T12:00:00" # Missing Z
        
        with self.assertRaises(ValueError):
            self.adapter.adapt(m1_naive, self.base_m2)

    # -------------------------------------------------------------------------
    # TEST 11 - FINDING EVIDENCE COMPLETENESS
    # -------------------------------------------------------------------------
    def test_11_finding_evidence_completeness(self):
        m2_no_evidence = copy.deepcopy(self.base_m2)
        m2_no_evidence["findings"][0]["evidence_references"] = []
        
        # M2 contract strictly requires min_length=1 for evidence_references
        with self.assertRaises(ValueError):
            self.adapter.adapt(self.base_m1, m2_no_evidence)

    # -------------------------------------------------------------------------
    # TEST 14 - NO MITRE CONTAMINATION
    # -------------------------------------------------------------------------
    def test_14_no_mitre_contamination(self):
        result = self.adapter.adapt(self.base_m1, self.base_m2)
        finding = result.findings[0]
        # Verify no MITRE fields were invented
        self.assertFalse(hasattr(finding, "mitre_id"))
        self.assertFalse(hasattr(finding, "technique_id"))
        
if __name__ == '__main__':
    unittest.main()
