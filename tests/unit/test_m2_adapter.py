import unittest
import json
from pathlib import Path
import jsonschema

from src.shared.contract_validation import ContractValidator
from src.m3_correlation.adapters.m1_adapter import M1Adapter
from src.m3_correlation.adapters.m2_adapter import M2Adapter

class TestM2Adapter(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.adapter = M2Adapter(self.validator)
        
        m2_fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "findings" / "finding-v1-scenario-001.json"
        with open(m2_fixture_path, 'r', encoding='utf-8') as f:
            self.scenario_001 = json.load(f)

    def test_scenario_001_loads_successfully(self):
        ctx = self.adapter.adapt(self.scenario_001)
        
        self.assertEqual(len(ctx.findings), 1)
        f_ref = ctx.findings[0]
        
        self.assertEqual(f_ref.finding_id, "FINDING-001")
        self.assertEqual(f_ref.finding_type, "potential_beaconing")
        self.assertEqual(f_ref.severity, "medium")
        self.assertEqual(f_ref.confidence_score, 0.85)
        
        self.assertIsNotNone(f_ref.first_seen.tzinfo)
        self.assertIsNotNone(f_ref.last_seen.tzinfo)
        
        entity_ids = [e.entity_id for e in ctx.entities]
        
        self.assertIn("flow:FLOW-001", entity_ids)
        self.assertIn("protocol_event:EVENT-001", entity_ids)
        self.assertIn("ip:203.0.113.10", entity_ids)
        self.assertIn("finding:FINDING-001", entity_ids)
        
        flow_ent = next(e for e in ctx.entities if e.entity_id == "flow:FLOW-001")
        self.assertEqual(flow_ent.attributes["original_m2_id"], "FLOW-001")
        
        self.assertTrue(len(ctx.relationships) > 0)
        rel = next(r for r in ctx.relationships if r.source_entity_id == "finding:FINDING-001" and r.target_entity_id == "flow:FLOW-001")
        self.assertEqual(rel.relationship_type, "explicit_reference")
        
        finding_ent = next(e for e in ctx.entities if e.entity_id == "finding:FINDING-001")
        self.assertEqual(finding_ent.attributes["provenance"]["engine"], "analysis-engine")
        
        for r in ctx.relationships:
            self.assertEqual(r.relationship_type, "explicit_reference")

    def test_invalid_finding_input_rejected(self):
        bad_payload = json.loads(json.dumps(self.scenario_001))
        bad_payload["unknown_property"] = "bad"
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            self.adapter.adapt(bad_payload)

    def test_malformed_timestamp_rejected(self):
        bad_payload = json.loads(json.dumps(self.scenario_001))
        bad_payload["first_seen"] = "2026-08-15"
        with self.assertRaises(ValueError):
            self.adapter.adapt(bad_payload)

    def test_invalid_confidence_rejected(self):
        bad_payload = json.loads(json.dumps(self.scenario_001))
        bad_payload["confidence_score"] = 5.0
        with self.assertRaises(ValueError):
            self.adapter.adapt(bad_payload)

    def test_integration_with_m1_context(self):
        m1_fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "network_intelligence" / "network-intelligence-v1-m1-phase1.json"
        with open(m1_fixture_path, 'r', encoding='utf-8') as f:
            m1_scenario = json.load(f)
            
        m1_adapter = M1Adapter(self.validator)
        ctx = m1_adapter.adapt(m1_scenario)
        
        ctx = self.adapter.adapt(self.scenario_001, ctx)
        
        entity_ids = [e.entity_id for e in ctx.entities]
        
        self.assertIn("flow:FLOW-001", entity_ids)
        self.assertIn("protocol_event:EVT-001", entity_ids)
        self.assertIn("ip:203.0.113.10", entity_ids)
        self.assertIn("domain:suspicious.example.com", entity_ids)
        self.assertIn("finding:FINDING-001", entity_ids)
        
        ip_203_entities = [e for e in ctx.entities if e.entity_id == "ip:203.0.113.10"]
        self.assertEqual(len(ip_203_entities), 1)
        
        flow_entities = [e for e in ctx.entities if e.entity_id == "flow:FLOW-001"]
        self.assertEqual(len(flow_entities), 1)
        self.assertEqual(flow_entities[0].attributes["protocol"], "tcp")

    def test_m2_evidence_reference_preservation(self):
        """Verify M2 evidence reference_id, role, and evidence_type are preserved deterministically."""
        ctx = self.adapter.adapt(self.scenario_001)
        ev_refs = ctx.evidence_references
        self.assertEqual(len(ev_refs), 2)
        
        flow_ev = next(e for e in ev_refs if e.evidence_id == "ev-FLOW-001")
        self.assertEqual(flow_ev.evidence_type, "flow")
        self.assertEqual(flow_ev.source_id, "FLOW-001")

        event_ev = next(e for e in ev_refs if e.evidence_id == "ev-EVENT-001")
        self.assertEqual(event_ev.evidence_type, "log") # protocol_event safely mapped to log
        self.assertEqual(event_ev.source_id, "EVENT-001")

    def test_unsupported_evidence_reference_type_rejected(self):
        """Verify unsupported evidence reference type raises ValueError during EvidenceReference creation."""
        bad_payload = json.loads(json.dumps(self.scenario_001))
        bad_payload["evidence_references"].append({
            "reference_type": "invalid_type",
            "reference_id": "BAD-001",
            "role": "supporting"
        })
        with self.assertRaises(ValueError):
            self.adapter.adapt(bad_payload)
