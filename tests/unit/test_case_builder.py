import unittest
import json
from pathlib import Path

from src.shared.contract_validation import ContractValidator
from src.m3_correlation.adapters.m1_adapter import M1Adapter
from src.m3_correlation.adapters.m2_adapter import M2Adapter
from src.m3_correlation.correlation.correlation_engine import CorrelationEngine
from src.m3_correlation.investigation.case_builder import InvestigationCaseBuilder
from src.m3_correlation.domain.investigation import InvestigationContext

class TestCaseBuilder(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.m1_adapter = M1Adapter(self.validator)
        self.m2_adapter = M2Adapter(self.validator)
        self.engine = CorrelationEngine()
        self.builder = InvestigationCaseBuilder(self.validator)
        
        m1_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "network_intelligence" / "network-intelligence-v1-m1-phase1.json"
        with open(m1_path, 'r', encoding='utf-8') as f:
            self.m1_payload = json.load(f)
            
        m2_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "findings" / "finding-v1-scenario-001.json"
        with open(m2_path, 'r', encoding='utf-8') as f:
            self.m2_payload = json.load(f)

    def test_full_pipeline_scenario_001(self):
        ctx = self.m1_adapter.adapt(self.m1_payload)
        ctx = self.m2_adapter.adapt(self.m2_payload, ctx)
        ctx = self.engine.correlate(ctx)
        
        # 1. Assembled into InvestigationCase
        doc = self.builder.build(ctx)
        
        # 2. Schema validates successfully (implicitly tested by build() internally calling validate)
        self.assertEqual(doc["schema_version"], "investigation-case-v1.1")
        
        # 3. acquisition_id preserved -> fallback into case_id
        self.assertEqual(doc["case_id"], "CASE-ACQ-001")
        
        # 4. finding_id preserved
        self.assertTrue(any(f["finding_id"] == "FINDING-001" for f in doc["findings"]))
        
        # 5. entity IDs preserved and protocol_event type is natively supported
        ent_ids = [e["entity_id"] for e in doc["entities"]]
        ent_types = [e["entity_type"] for e in doc["entities"]]
        self.assertIn("ip:203.0.113.10", ent_ids)
        self.assertIn("flow:FLOW-001", ent_ids)
        self.assertIn("domain:suspicious.example.com", ent_ids)
        self.assertIn("protocol_event:EVT-001", ent_ids)
        self.assertIn("protocol_event", ent_types)
        
        # 6. Timeline chronologically ordered (correlation engine sorts it) and complete entity_ids
        timestamps = [t["timestamp"] for t in doc["timeline"]]
        self.assertTrue(timestamps[0] <= timestamps[-1])
        t_dns = next(t for t in doc["timeline"] if t["event_id"] == "EVT-001")
        self.assertIn("entity_ids", t_dns)
        self.assertGreaterEqual(len(t_dns["entity_ids"]), 2)
        
        # 7. Evidence references preserved
        ev_ids = [e["evidence_id"] for e in doc["evidence_references"]]
        self.assertTrue("ev-EVT-001" in ev_ids or "ev-EVENT-001" in ev_ids)
        
        # 8. Relationships are now explicitly supported and not dropped
        self.assertGreater(len(doc["relationships"]), 0)
        self.assertTrue(any(r["relationship_type"] == "queried" for r in doc["relationships"]))
        
        # 9. attack_chain status is none
        self.assertEqual(doc["attack_chain"]["status"], "none")
        
        # 10. Building twice produces deterministic equivalent output
        doc2 = self.builder.build(ctx)
        self.assertEqual(json.dumps(doc, sort_keys=True), json.dumps(doc2, sort_keys=True))

    def test_invalid_context_handled_safely(self):
        ctx = InvestigationContext()
        # 11. No acquisition_id, no case_id -> ValueError
        with self.assertRaises(ValueError):
            self.builder.build(ctx)
            
        ctx.acquisition_id = "TEST-123"
        # No timeline -> ValueError for deterministic times
        with self.assertRaises(ValueError):
            self.builder.build(ctx)

    def test_case_id_determinism(self):
        """Verify building InvestigationContext twice yields identical case_id and timestamps."""
        ctx = self.m1_adapter.adapt(self.m1_payload)
        ctx = self.m2_adapter.adapt(self.m2_payload, ctx)
        ctx = self.engine.correlate(ctx)

        doc1 = self.builder.build(ctx)
        doc2 = self.builder.build(ctx)

        self.assertEqual(doc1["case_id"], doc2["case_id"])
        self.assertEqual(doc1["created_at"], doc2["created_at"])
        self.assertEqual(doc1["updated_at"], doc2["updated_at"])

    def test_referential_integrity_check_fails_on_undeclared_evidence(self):
        """Verify builder raises ValueError if timeline event references an undeclared evidence ID."""
        ctx = self.m1_adapter.adapt(self.m1_payload)
        ctx = self.m2_adapter.adapt(self.m2_payload, ctx)
        ctx = self.engine.correlate(ctx)

        # Introduce an undeclared evidence ID reference in timeline
        ctx.timeline_events[0].evidence_ids.append("ev-UNDECLARED-999")

        with self.assertRaises(ValueError) as cm:
            self.builder.build(ctx)
        self.assertIn("ev-UNDECLARED-999", str(cm.exception))
