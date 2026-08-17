import unittest
import json
from pathlib import Path

from backend.app.shared.contract_validation import ContractValidator
from backend.app.engines.correlation.adapters.m1_adapter import M1Adapter
from backend.app.engines.correlation.adapters.m2_adapter import M2Adapter
from backend.app.engines.correlation.correlation.correlation_engine import CorrelationEngine
from backend.app.engines.correlation.domain.investigation import InvestigationContext
from backend.app.engines.correlation.domain.entity import Entity
from backend.app.engines.correlation.domain.timeline import TimelineEvent
from datetime import datetime, timezone, timedelta

class TestCorrelationEngine(unittest.TestCase):
    def setUp(self):
        validator = ContractValidator()
        self.m1_adapter = M1Adapter(validator)
        self.m2_adapter = M2Adapter(validator)
        self.engine = CorrelationEngine()
        
        m1_path = Path(__file__).resolve().parent.parent.parent.parent / "fixtures" / "network_intelligence" / "network-intelligence-v1-m1-phase1.json"
        with open(m1_path, 'r', encoding='utf-8') as f:
            self.m1_payload = json.load(f)
            
        m2_path = Path(__file__).resolve().parent.parent.parent.parent / "fixtures" / "findings" / "finding-v1-scenario-001.json"
        with open(m2_path, 'r', encoding='utf-8') as f:
            self.m2_payload = json.load(f)

    def test_scenario_001_correlation(self):
        ctx = self.m1_adapter.adapt(self.m1_payload)
        ctx = self.m2_adapter.adapt(self.m2_payload, ctx)
        
        ctx = self.engine.correlate(ctx)
        
        rels = ctx.relationships
        
        # 1. Flow <-> protocol event
        self.assertTrue(any(r.source_entity_id == "protocol_event:EVT-001" and 
                            r.target_entity_id == "flow:FLOW-001" and 
                            r.relationship_type == "observed_in" for r in rels))
                            
        # 2. DNS <-> IP
        self.assertTrue(any(r.source_entity_id == "protocol_event:EVT-001" and 
                            r.target_entity_id == "ip:203.0.113.10" and 
                            r.relationship_type == "resolved_to" for r in rels))
                            
        # 3. DNS <-> Domain
        self.assertTrue(any(r.source_entity_id == "protocol_event:EVT-001" and 
                            r.target_entity_id == "domain:suspicious.example.com" and 
                            r.relationship_type == "queried" for r in rels))
                            
        # 4. Artifact <-> protocol event
        self.assertTrue(any(r.source_entity_id == "domain:suspicious.example.com" and 
                            r.target_entity_id == "protocol_event:EVT-001" and 
                            r.relationship_type == "derived_from" for r in rels))
                            
        # 5. Artifact <-> flow
        self.assertTrue(any(r.source_entity_id == "domain:suspicious.example.com" and 
                            r.target_entity_id == "flow:FLOW-001" and 
                            r.relationship_type == "associated_with" for r in rels))
                            
        # 6. Finding <-> explicit evidence
        self.assertTrue(any(r.source_entity_id == "finding:FINDING-001" and 
                            r.relationship_type == "supported_by" for r in rels))
                            
        # Preserve provenance/role in finding relationships
        finding_rel = next(r for r in rels if r.relationship_type == "supported_by" and r.target_entity_id == "flow:FLOW-001")
        self.assertEqual(finding_rel.attributes.get("role"), "primary")
        
        # 7. Chronological ordering
        if len(ctx.timeline_events) >= 2:
            self.assertTrue(ctx.timeline_events[0].timestamp <= ctx.timeline_events[1].timestamp)
            
        # 10. Running twice doesn't duplicate relationships (11. Deterministic)
        count_before = len(ctx.relationships)
        ctx = self.engine.correlate(ctx)
        self.assertEqual(len(ctx.relationships), count_before)

    def test_negative_unrelated_ip_dns(self): # 8
        ctx = InvestigationContext()
        pe = Entity("protocol_event:1", "protocol_event", "1", attributes={
            "protocol": "dns",
            "data": {"answers": ["1.1.1.1"]}
        })
        ip_ent = Entity("ip:2.2.2.2", "ip", "2.2.2.2")
        ctx.add_entity(pe)
        ctx.add_entity(ip_ent)
        
        ctx = self.engine.correlate(ctx)
        self.assertEqual(len(ctx.relationships), 0)

    def test_negative_invalid_ip_dns(self):
        ctx = InvestigationContext()
        pe = Entity("protocol_event:1", "protocol_event", "1", attributes={
            "protocol": "dns",
            "data": {"answers": ["not-an-ip"]}
        })
        bad_ip = Entity("ip:not-an-ip", "ip", "not-an-ip")
        ctx.add_entity(pe)
        ctx.add_entity(bad_ip)
        
        ctx = self.engine.correlate(ctx)
        self.assertEqual(len(ctx.relationships), 0)
        
    def test_negative_unrelated_flow(self): # 9
        ctx = InvestigationContext()
        pe = Entity("protocol_event:1", "protocol_event", "1", attributes={"flow_id": "F1"})
        flow_ent = Entity("flow:F2", "flow", "F2")
        ctx.add_entity(pe)
        ctx.add_entity(flow_ent)
        
        ctx = self.engine.correlate(ctx)
        self.assertEqual(len(ctx.relationships), 0)

    def test_chronological_sorting(self): # 12. No attack chain created solely from temporal ordering
        ctx = InvestigationContext()
        t2 = datetime(2026, 8, 15, 10, 5, tzinfo=timezone.utc)
        t1 = datetime(2026, 8, 15, 10, 0, tzinfo=timezone.utc)
        
        e1 = TimelineEvent("evt-1", t2, "test", "Later event")
        e2 = TimelineEvent("evt-2", t1, "test", "Earlier event")
        ctx.timeline_events = [e1, e2]
        
        ctx = self.engine.correlate(ctx)
        self.assertEqual(ctx.timeline_events[0].event_id, "evt-2")
        self.assertEqual(ctx.timeline_events[1].event_id, "evt-1")
        
        # Verify no implicit attack chain relationships were added
        self.assertEqual(len(ctx.relationships), 0)
