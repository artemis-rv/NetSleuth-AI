import unittest
from datetime import datetime

from app.engines.correlation.domain.input import M3InvestigationInput, EvidenceIndex, TelemetryCapability
from app.contracts.analysis import Finding, EvidenceReference
from app.contracts.network_intelligence import Flow, ProtocolEvent
from app.engines.correlation.mitre.repository import MitreKnowledgeRepository
from app.engines.correlation.mitre.mapper import MitreMapper
from app.engines.correlation.mitre.models import MappingStatus

class TestMitreMapper(unittest.TestCase):
    def setUp(self):
        self.repo = MitreKnowledgeRepository()
        self.mapper = MitreMapper(self.repo)

    def _build_input(self, activity_class: str, has_http=False, has_tls=False, has_dns=False, has_flow=True, risk_score=0.50) -> M3InvestigationInput:
        finding_id = "FND-001"
        finding = Finding.model_construct(
            finding_id=finding_id,
            acquisition_id="ACQ-1",
            activity_class=activity_class,
            classification_confidence=0.9,
            risk_score=risk_score,
            anomaly_score=0.8,
            anomaly_detected=True,
            model_version="1.0",
            evidence_references=[
                EvidenceReference.model_construct(flow_ids=["FLOW-001"], event_ids=[], artifact_ids=[], rationale="test")
            ]
        )
        
        index = EvidenceIndex.model_construct(
            flows={"FLOW-001": Flow.model_construct(flow_id="FLOW-001")},
            events={},
            artifacts={},
            findings={finding_id: finding}
        )
        
        telemetry = TelemetryCapability.model_construct(
            network_flow=has_flow,
            dns=has_dns,
            http=has_http,
            tls=has_tls
        )
        
        return M3InvestigationInput.model_construct(
            acquisition_id="ACQ-1",
            network_package_id="NET-1",
            findings_package_id="FND-PKG-1",
            telemetry_capabilities=telemetry,
            evidence_index=index,
            network_flows=[],
            protocol_events=[],
            artifacts=[],
            findings=[]
        )

    def test_c2_http_tls_evidence_t1071_001_candidate(self):
        ctx = self._build_input("C2_MALWARE_COMMUNICATION", has_http=True)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        
        # Should map T1071.001
        m = next((m for m in mappings if m.technique_id == "T1071.001"), None)
        self.assertIsNotNone(m)
        self.assertEqual(m.mapping_status, MappingStatus.SUPPORTED)

    def test_c2_dns_evidence_t1071_004_candidate(self):
        ctx = self._build_input("C2_MALWARE_COMMUNICATION", has_dns=True)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        
        m = next((m for m in mappings if m.technique_id == "T1071.004"), None)
        self.assertIsNotNone(m)
        self.assertEqual(m.mapping_status, MappingStatus.SUPPORTED)

    def test_c2_without_matching_evidence_no_unsupported_mapping(self):
        ctx = self._build_input("C2_MALWARE_COMMUNICATION", has_dns=False, has_http=False, has_tls=False)
        # Should drop T1071.001 and T1071.004 because INSUFFICIENT_EVIDENCE
        mappings = self.mapper.map_finding(ctx, "FND-001")
        
        self.assertNotIn("T1071.001", [m.technique_id for m in mappings])
        self.assertNotIn("T1071.004", [m.technique_id for m in mappings])
        
        # But it should emit T1095 since it's a non-app fallback
        self.assertIn("T1095", [m.technique_id for m in mappings])

    def test_dns_anomaly_plus_dns_evidence_t1071_004(self):
        ctx = self._build_input("DNS_ANOMALY_TUNNELING", has_dns=True)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertEqual(len(mappings), 1)
        self.assertEqual(mappings[0].technique_id, "T1071.004")
        self.assertEqual(mappings[0].mapping_status, MappingStatus.SUPPORTED)

    def test_dns_anomaly_without_dns_evidence_insufficient(self):
        ctx = self._build_input("DNS_ANOMALY_TUNNELING", has_dns=False)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertEqual(len(mappings), 0)

    def test_scanning_with_flow_evidence_t1046(self):
        ctx = self._build_input("SCANNING_RECONNAISSANCE", has_flow=True)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertEqual(mappings[0].technique_id, "T1046")

    def test_scanning_missing_endpoint_telemetry_partial(self):
        ctx = self._build_input("SCANNING_RECONNAISSANCE", has_flow=True)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertEqual(mappings[0].mapping_status, MappingStatus.PARTIAL)
        self.assertEqual(mappings[0].mapping_confidence, 0.9 * 0.8) # Base * 0.8

    def test_possible_exfil_large_outbound_potential_or_partial(self):
        # Risk > 0.75 = PARTIAL
        ctx = self._build_input("POSSIBLE_EXFILTRATION", has_flow=True, risk_score=0.80)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertEqual(mappings[0].mapping_status, MappingStatus.PARTIAL)

        # Risk <= 0.75 = POTENTIAL
        ctx2 = self._build_input("POSSIBLE_EXFILTRATION", has_flow=True, risk_score=0.50)
        mappings2 = self.mapper.map_finding(ctx2, "FND-001")
        self.assertEqual(mappings2[0].mapping_status, MappingStatus.POTENTIAL)
        
    def test_large_outbound_alone_does_not_become_confirmed_t1041(self):
        ctx = self._build_input("POSSIBLE_EXFILTRATION", has_flow=True, risk_score=0.99)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        # Never SUPPORTED without endpoint
        self.assertNotEqual(mappings[0].mapping_status, MappingStatus.SUPPORTED)

    def test_suspicious_http_only_no_automatic_supported(self):
        ctx = self._build_input("SUSPICIOUS_WEB_ACTIVITY", has_http=True, risk_score=0.50)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertEqual(mappings[0].mapping_status, MappingStatus.POTENTIAL)

    def test_correlated_web_c2_evidence_supports_t1071_001(self):
        ctx = self._build_input("SUSPICIOUS_WEB_ACTIVITY", has_http=True, risk_score=0.90)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertEqual(mappings[0].mapping_status, MappingStatus.SUPPORTED)

    def test_every_mapping_contains_real_evidence_ids(self):
        ctx = self._build_input("SCANNING_RECONNAISSANCE", has_flow=True)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertIn("FLOW-001", mappings[0].evidence_ids)

    def test_invalid_evidence_reference_is_rejected(self):
        ctx = self._build_input("SCANNING_RECONNAISSANCE", has_flow=True)
        # Manually poison the reference
        # We need to bypass the frozen check, or just create a new input. 
        # Since Finding is frozen, let's just make a new EvidenceReference
        finding = ctx.evidence_index.findings["FND-001"]
        object.__setattr__(finding, "evidence_references", [EvidenceReference(flow_ids=["FAKE-123"], rationale="fake")])
        
        mappings = self.mapper.map_finding(ctx, "FND-001")
        # If no valid evidence remains, map_finding should return []
        self.assertEqual(len(mappings), 0)

    def test_mapping_confidence_within_bounds(self):
        ctx = self._build_input("SCANNING_RECONNAISSANCE", has_flow=True)
        finding = ctx.evidence_index.findings["FND-001"]
        object.__setattr__(finding, "classification_confidence", 1.5) # Force bypass validation
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertTrue(0.0 <= mappings[0].mapping_confidence <= 1.0)

    def test_mapping_is_deterministic(self):
        ctx = self._build_input("SCANNING_RECONNAISSANCE", has_flow=True)
        m1 = self.mapper.map_finding(ctx, "FND-001")[0]
        m2 = self.mapper.map_finding(ctx, "FND-001")[0]
        self.assertEqual(m1.mapping_id, m2.mapping_id)

    def test_attack_version_is_preserved(self):
        ctx = self._build_input("SCANNING_RECONNAISSANCE", has_flow=True)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertNotEqual(mappings[0].mitre_version, "Unknown")
        self.assertEqual(mappings[0].mitre_version, self.repo.mitre_version)

    def test_knowledge_profile_id_is_preserved(self):
        ctx = self._build_input("SCANNING_RECONNAISSANCE", has_flow=True)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertEqual(mappings[0].knowledge_profile_id, "netsleuth-network-evidence-v1")

    def test_multiple_candidate_techniques_evaluated_independently(self):
        ctx = self._build_input("C2_MALWARE_COMMUNICATION", has_dns=True, has_http=True)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        tech_ids = [m.technique_id for m in mappings]
        self.assertIn("T1071.001", tech_ids)
        self.assertIn("T1071.004", tech_ids)
        self.assertNotIn("T1095", tech_ids) # Because HTTP/DNS are present, T1095 drops to insufficient

    def test_no_mapping_for_unrelated_behavior(self):
        ctx = self._build_input("SOMETHING_ELSE")
        mappings = self.mapper.map_finding(ctx, "FND-001")
        self.assertEqual(len(mappings), 0)

    def test_no_technique_outside_scope_produced(self):
        ctx = self._build_input("C2_MALWARE_COMMUNICATION", has_dns=True, has_http=True)
        mappings = self.mapper.map_finding(ctx, "FND-001")
        allowed = {"T1071.001", "T1071.004", "T1095", "T1046", "T1041"}
        for m in mappings:
            self.assertIn(m.technique_id, allowed)

if __name__ == "__main__":
    unittest.main()
