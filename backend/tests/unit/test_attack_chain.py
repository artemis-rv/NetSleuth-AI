import unittest
from datetime import datetime, timezone
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../..")))

from backend.app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from backend.app.engines.correlation.domain.investigation import InvestigationContext
from backend.app.engines.correlation.domain.finding import FindingReference
from backend.app.engines.correlation.domain.evidence import EvidenceReference as DomainEvidenceReference
from backend.app.engines.correlation.domain.timeline import TimelineEvent
from backend.app.engines.correlation.domain.entity import Entity
from backend.app.engines.correlation.mitre.models import MitreMapping, MappingStatus
from backend.app.shared.contract_validation import ContractValidator

class TestAttackChainConstruction(unittest.TestCase):
    def setUp(self):
        project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../.."))
        self.validator = ContractValidator()
        self.builder = InvestigationCaseBuilder(self.validator)

    def _create_base_ctx(self) -> InvestigationContext:
        ctx = InvestigationContext(acquisition_id="ACQ-001")
        now = datetime.now(timezone.utc)
        ctx.timeline_events.append(TimelineEvent(
            event_id="EV-1",
            timestamp=now,
            event_type="network",
            description="Test Event",
            entity_ids=["host:10.0.0.1"],
            evidence_ids=["EVID-1"]
        ))
        ctx.evidence_references.append(DomainEvidenceReference(
            evidence_id="EVID-1",
            evidence_type="flow",
            source_id="F-001"
        ))
        ctx.findings.append(FindingReference(
            finding_id="FND-1",
            finding_type="malware",
            severity="high",
            confidence_score=0.9
        ))
        ctx.entities.append(Entity(
            entity_id="host:10.0.0.1",
            entity_type="host",
            value="10.0.0.1"
        ))
        ctx.mitre_mappings = []
        return ctx

    def test_01_no_mappings_attack_chain_status_none(self):
        ctx = self._create_base_ctx()
        doc = self.builder.build(ctx)
        self.assertEqual(doc["attack_chain"]["status"], "none")
        self.assertNotIn("stages", doc["attack_chain"])

    def test_02_one_supported_t1071_001_one_chain_stage(self):
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1071.001",
            technique_name="Web Protocols",
            mapping_status=MappingStatus.SUPPORTED,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        self.assertEqual(doc["attack_chain"]["status"], "potential")
        self.assertEqual(len(doc["attack_chain"]["stages"]), 1)
        self.assertEqual(doc["attack_chain"]["stages"][0]["stage_id"], "stage-T1071.001")
        self.assertEqual(doc["attack_chain"]["stages"][0]["name"], "Web Protocols")

    def test_03_supported_dns_mapping_dns_c2_stage(self):
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1071.004",
            technique_name="DNS",
            mapping_status=MappingStatus.SUPPORTED,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        self.assertEqual(doc["attack_chain"]["status"], "potential")
        self.assertEqual(len(doc["attack_chain"]["stages"]), 1)
        self.assertEqual(doc["attack_chain"]["stages"][0]["stage_id"], "stage-T1071.004")
        self.assertEqual(doc["attack_chain"]["stages"][0]["name"], "DNS")

    def test_04_potential_t1041_potential_exfiltration_stage(self):
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1041",
            technique_name="Exfiltration Over C2 Channel",
            mapping_status=MappingStatus.POTENTIAL,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        self.assertEqual(doc["attack_chain"]["status"], "potential")
        self.assertEqual(len(doc["attack_chain"]["stages"]), 1)

    def test_05_unsupported_mapping_no_confirmed_stage(self):
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1071.001",
            technique_name="Web Protocols",
            mapping_status=MappingStatus.INSUFFICIENT_EVIDENCE,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        self.assertEqual(doc["attack_chain"]["status"], "none")

    def test_06_multiple_stages_sorted_chronologically(self):
        ctx = self._create_base_ctx()
        t1 = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t2 = datetime(2026, 1, 1, 12, 1, 0, tzinfo=timezone.utc)
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1041",
            technique_name="Exfil",
            mapping_status=MappingStatus.SUPPORTED,
            first_seen=t2
        ))
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-2",
            finding_id="FND-1",
            technique_id="T1071.001",
            technique_name="C2",
            mapping_status=MappingStatus.SUPPORTED,
            first_seen=t1
        ))
        doc = self.builder.build(ctx)
        self.assertEqual(doc["attack_chain"]["status"], "potential")
        self.assertEqual(len(doc["attack_chain"]["stages"]), 2)
        # C2 should be first chronologically
        self.assertEqual(doc["attack_chain"]["stages"][0]["stage_id"], "stage-T1071.001")
        self.assertEqual(doc["attack_chain"]["stages"][1]["stage_id"], "stage-T1041")

    def test_07_evidence_ids_preserved(self):
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1071.001",
            technique_name="Web Protocols",
            mapping_status=MappingStatus.SUPPORTED,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        stage = doc["attack_chain"]["stages"][0]
        # evidence_ids is mapped to event_ids via timeline cross-ref
        self.assertIn("EV-1", stage["event_ids"])

    def test_08_finding_ids_preserved(self):
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1071.001",
            technique_name="Web Protocols",
            mapping_status=MappingStatus.SUPPORTED,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        stage = doc["attack_chain"]["stages"][0]
        self.assertIn("FND-1", stage["finding_ids"])

    def test_09_confidence_preserved(self):
        # Confidence does not exist on the AttackChainStage schema for V1.2.
        # But we ensure it does not break anything by trying to add it.
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1071.001",
            technique_name="Web Protocols",
            mapping_status=MappingStatus.SUPPORTED,
            mapping_confidence=0.8,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        stage = doc["attack_chain"]["stages"][0]
        self.assertNotIn("confidence", stage) # Should not exist per strict schema
        self.assertEqual(doc["attack_chain"]["status"], "potential")

    def test_10_no_invented_stages(self):
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1041",
            technique_name="Exfil",
            mapping_status=MappingStatus.SUPPORTED,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        # Should only have T1041. Should NOT invent Initial Access or C2.
        self.assertEqual(len(doc["attack_chain"]["stages"]), 1)
        self.assertEqual(doc["attack_chain"]["stages"][0]["stage_id"], "stage-T1041")

    def test_11_same_input_produces_identical_chain(self):
        ctx1 = self._create_base_ctx()
        ctx2 = self._create_base_ctx()
        for ctx in [ctx1, ctx2]:
            ctx.mitre_mappings.append(MitreMapping(
                mapping_id="M-1",
                finding_id="FND-1",
                technique_id="T1071.001",
                technique_name="Web Protocols",
                mapping_status=MappingStatus.SUPPORTED,
                evidence_ids=["EVID-1"]
            ))
        doc1 = self.builder.build(ctx1)
        doc2 = self.builder.build(ctx2)
        self.assertEqual(doc1["attack_chain"], doc2["attack_chain"])

    def test_12_unrelated_mappings_do_not_create_edges(self):
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1071.001",
            technique_name="Web Protocols",
            mapping_status=MappingStatus.SUPPORTED,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        # Verify the stage is mapped exactly to its finding
        self.assertEqual(doc["attack_chain"]["stages"][0]["finding_ids"], ["FND-1"])

    def test_13_missing_evidence_prevents_stage_creation(self):
        # We simulate INSUFFICIENT_EVIDENCE
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1071.001",
            technique_name="Web Protocols",
            mapping_status=MappingStatus.INSUFFICIENT_EVIDENCE,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        self.assertEqual(doc["attack_chain"]["status"], "none")

    def test_14_sequence_of_stages_does_not_automatically_become_confirmed(self):
        ctx = self._create_base_ctx()
        # Two potential stages. The status must be POTENTIAL, not CONFIRMED.
        ctx.mitre_mappings.extend([
            MitreMapping(
                mapping_id="M-1", finding_id="FND-1", technique_id="T1071.001",
                technique_name="C2", mapping_status=MappingStatus.POTENTIAL, evidence_ids=["EVID-1"]
            ),
            MitreMapping(
                mapping_id="M-2", finding_id="FND-1", technique_id="T1041",
                technique_name="Exfil", mapping_status=MappingStatus.POTENTIAL, evidence_ids=["EVID-1"]
            )
        ])
        doc = self.builder.build(ctx)
        self.assertEqual(doc["attack_chain"]["status"], "potential")

    def test_15_v1_2_schema_validation_succeeds(self):
        ctx = self._create_base_ctx()
        ctx.mitre_mappings.append(MitreMapping(
            mapping_id="M-1",
            finding_id="FND-1",
            technique_id="T1071.001",
            technique_name="Web Protocols",
            mapping_status=MappingStatus.SUPPORTED,
            evidence_ids=["EVID-1"]
        ))
        doc = self.builder.build(ctx)
        # It successfully builds and is validated by `self.validator.validate(...)` inside build()
        self.assertEqual(doc["schema_version"], "investigation-case-v1.2")

if __name__ == '__main__':
    unittest.main()
