import unittest
import os
from datetime import datetime, timezone
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..", "backend")))

from app.engines.correlation.mitre.repository import MitreKnowledgeRepository
from app.engines.correlation.mitre.mapper import MitreMapper
from app.engines.correlation.mitre.models import MappingStatus
from app.engines.correlation.domain.input import M3InvestigationInput, EvidenceIndex, TelemetryCapability
from app.engines.correlation.domain.finding import FindingReference
from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from app.shared.contract_validation import ContractValidator
from app.contracts.analysis import Finding, EvidenceReference
from app.contracts.network_intelligence import Flow
from app.engines.reporting.case_adapter import M3ToM4EvidenceAdapter
from app.engines.reporting.report_engine import ReportEngine
from app.engines.correlation.domain.timeline import TimelineEvent
from app.engines.correlation.domain.entity import Entity
from app.engines.correlation.domain.evidence import EvidenceReference as DomainEvidenceReference

class TestM3M4Integration(unittest.TestCase):
    def setUp(self):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
        self.validator = ContractValidator()
        self.repo = MitreKnowledgeRepository()
        self.mapper = MitreMapper(self.repo)
        self.case_builder = InvestigationCaseBuilder(self.validator)
        self.adapter = M3ToM4EvidenceAdapter(self.validator)
        self.report_engine = ReportEngine(self.validator)

    def test_m3_to_m4_end_to_end_v1_2(self):
        # 1. Create upstream Finding and Flow 
        finding_id = "FND-001"
        finding = Finding.model_construct(
            finding_id=finding_id,
            acquisition_id="ACQ-1",
            activity_class="C2_MALWARE_COMMUNICATION",
            classification_confidence=0.9,
            risk_score=0.8,
            anomaly_score=0.8,
            anomaly_detected=True,
            model_version="1.0",
            evidence_references=[
                EvidenceReference.model_construct(flow_ids=["FLOW-001"], event_ids=[], artifact_ids=[], rationale="test")
            ]
        )
        
        index = EvidenceIndex.model_construct(
            flows={"FLOW-001": Flow.model_construct(flow_id="FLOW-001", protocol="http")},
            events={},
            artifacts={},
            findings={finding_id: finding}
        )
        
        telemetry = TelemetryCapability.model_construct(
            network_flow=True,
            dns=False,
            http=True,
            tls=False
        )
        
        input_ctx = M3InvestigationInput.model_construct(
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

        # 2. Run MITRE Mapper
        mitre_mappings = self.mapper.map_finding(input_ctx, finding_id)
        self.assertTrue(len(mitre_mappings) > 0)
        self.assertEqual(mitre_mappings[0].mapping_status, MappingStatus.SUPPORTED)

        # 3. Create Investigation Context
        now = datetime.now(timezone.utc)
        inv_ctx = InvestigationContext(
            case_id="CASE-INT-001",
            acquisition_id="ACQ-1"
        )
        
        # Add basic required entities and timeline to make a valid case
        inv_ctx.add_entity(Entity(entity_id="host:10.0.0.1", entity_type="host", value="10.0.0.1"))
        inv_ctx.timeline_events.append(TimelineEvent(
            event_id="TE1", 
            timestamp=now, 
            event_type="network", 
            description="Test Event",
            entity_ids=["host:10.0.0.1"],
            evidence_ids=["ev-01"]
        ))
        inv_ctx.evidence_references.append(DomainEvidenceReference(
            evidence_id="ev-01",
            evidence_type="flow",
            source_id="FLOW-001"
        ))
        
        inv_ctx.findings.append(FindingReference(finding_id=finding_id, finding_type="malware", severity="high", confidence_score=0.9))
        
        # Inject the mitre_mappings
        inv_ctx.mitre_mappings = mitre_mappings

        # 4. Build Investigation Case (V1.2)
        case_doc = self.case_builder.build(inv_ctx)
        
        self.assertEqual(case_doc["schema_version"], "investigation-case-v1.2")
        self.assertIn("mitre_provenance", case_doc)
        self.assertEqual(case_doc["mitre_provenance"]["version"], "19.2")
        self.assertEqual(len(case_doc["mitre_mappings"]), 1)
        self.assertEqual(case_doc["mitre_mappings"][0]["technique_id"], "T1071.001")
        self.assertEqual(case_doc["mitre_mappings"][0]["mapping_status"], "SUPPORTED")
        
        # 5. Process through M4 Adapter
        evidence_package = self.adapter.adapt(case_doc)
        self.assertIsNotNone(evidence_package)
        self.assertEqual(evidence_package.case_id, "CASE-INT-001")
        self.assertEqual(evidence_package.schema_version, "investigation-case-v1.2")
        
        # 6. Generate M4 Report
        # Mocking an empty EvidenceIntegrity list for this test
        report_doc = self.report_engine.generate_report(case_doc, [])
        self.assertIsNotNone(report_doc)
        self.assertEqual(report_doc["schema_version"], "report-v1")
        self.assertEqual(report_doc["case_id"], "CASE-INT-001")
        # Attack Chain assertions
        self.assertIn("attack_chain", case_doc)
        attack_chain = case_doc["attack_chain"]
        self.assertEqual(attack_chain["status"], "potential")
        self.assertEqual(len(attack_chain["stages"]), 1)
        self.assertEqual(attack_chain["stages"][0]["stage_id"], "stage-T1071.001")

if __name__ == '__main__':
    unittest.main()
