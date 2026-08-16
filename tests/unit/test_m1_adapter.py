import unittest
import json
from pathlib import Path
import jsonschema

from src.shared.contract_validation import ContractValidator
from src.m3_correlation.adapters.m1_adapter import M1Adapter

class TestM1Adapter(unittest.TestCase):
    def setUp(self):
        self.validator = ContractValidator()
        self.adapter = M1Adapter(self.validator)
        
        fixture_path = Path(__file__).resolve().parent.parent.parent / "fixtures" / "network_intelligence" / "network-intelligence-v1-m1-phase1.json"
        with open(fixture_path, 'r', encoding='utf-8') as f:
            self.scenario_001 = json.load(f)

    def test_scenario_001_loads_successfully(self):
        ctx = self.adapter.adapt(self.scenario_001)
        
        # 2. acquisition_id preserved
        self.assertEqual(ctx.acquisition_id, "ACQ-001")
        
        entity_ids = [e.entity_id for e in ctx.entities]
        
        # 3-7. Check identities
        self.assertIn("ip:10.0.0.10", entity_ids)
        self.assertIn("ip:203.0.113.10", entity_ids)
        self.assertIn("flow:FLOW-001", entity_ids)
        self.assertIn("protocol_event:EVT-001", entity_ids)
        self.assertIn("domain:suspicious.example.com", entity_ids)
        
        # 8. DNS evidence uses evidence_type = dns
        dns_evidence = next(ev for ev in ctx.evidence_references if ev.source_id == "EVT-001")
        self.assertEqual(dns_evidence.evidence_type, "dns")
        
        # 9. timestamps timezone aware UTC
        for e in ctx.entities:
            if e.first_seen:
                self.assertIsNotNone(e.first_seen.tzinfo)
                self.assertEqual(e.first_seen.tzinfo.utcoffset(e.first_seen).total_seconds(), 0)
                
        # 10. Provenance preserved
        flow_ent = next(e for e in ctx.entities if e.entity_id == "flow:FLOW-001")
        self.assertEqual(flow_ent.attributes["provenance"]["source_log"], "conn.log")
        
        # 11. Duplicate insertion check
        ip_203_entities = [e for e in ctx.entities if e.entity_id == "ip:203.0.113.10"]
        self.assertEqual(len(ip_203_entities), 1)
        
        # 11. Timeline events created
        self.assertEqual(len(ctx.timeline_events), 2)
        self.assertEqual(ctx.timeline_events[0].event_id, "EVT-001")

    def test_malformed_timestamp_rejected(self):
        bad_payload = json.loads(json.dumps(self.scenario_001))
        bad_payload["flows"][0]["timestamp"] = "bad-date"
        with self.assertRaises(ValueError):
            self.adapter.adapt(bad_payload)
            
    def test_invalid_m1_input_rejected(self):
        bad_payload = json.loads(json.dumps(self.scenario_001))
        bad_payload["unknown_field"] = "bad"
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            self.adapter.adapt(bad_payload)
            
    def test_naive_timestamp_rejected(self):
        with self.assertRaises(ValueError):
            self.adapter._parse_timestamp("2026-08-14T18:30:22") # no timezone

    def test_flow_and_artifact_evidence_registration(self):
        """Verify M1 adapter explicitly registers EvidenceReference for flows and artifacts."""
        ctx = self.adapter.adapt(self.scenario_001)
        ev_ids = [ev.evidence_id for ev in ctx.evidence_references]
        self.assertIn("ev-FLOW-001", ev_ids)
        self.assertIn("ev-ART-001", ev_ids)
        
        flow_ev = next(ev for ev in ctx.evidence_references if ev.evidence_id == "ev-FLOW-001")
        self.assertEqual(flow_ev.evidence_type, "flow")
        self.assertEqual(flow_ev.source_id, "FLOW-001")

        art_ev = next(ev for ev in ctx.evidence_references if ev.evidence_id == "ev-ART-001")
        self.assertEqual(art_ev.evidence_type, "artifact")
        self.assertEqual(art_ev.source_id, "ART-001")
