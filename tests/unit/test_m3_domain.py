import unittest
from datetime import datetime, timezone

from src.m3_correlation.domain.entity import Entity
from src.m3_correlation.domain.relationship import Relationship
from src.m3_correlation.domain.timeline import TimelineEvent
from src.m3_correlation.domain.finding import FindingReference
from src.m3_correlation.domain.evidence import EvidenceReference
from src.m3_correlation.domain.investigation import InvestigationContext

class TestM3Domain(unittest.TestCase):
    def test_entity_creation(self):
        ent = Entity(
            entity_id="ip:203.0.113.10",
            entity_type="ip",
            value="203.0.113.10",
            first_seen=datetime.now(timezone.utc)
        )
        self.assertEqual(ent.entity_id, "ip:203.0.113.10")

    def test_entity_namespace_value_identity(self):
        ent1 = Entity(entity_id="ip:203.0.113.10", entity_type="ip", value="203.0.113.10")
        ent2 = Entity(entity_id="domain:203.0.113.10", entity_type="domain", value="203.0.113.10")
        self.assertNotEqual(ent1.entity_id, ent2.entity_id)
        self.assertNotEqual(ent1, ent2)

    def test_invalid_entity_id_rejected(self):
        with self.assertRaises(ValueError):
            Entity(entity_id="", entity_type="ip", value="1.1.1.1")
        
        with self.assertRaises(ValueError):
            Entity(entity_id="no_namespace_here", entity_type="ip", value="1.1.1.1")

    def test_relationship_creation(self):
        rel = Relationship(
            relationship_id="rel-001",
            source_entity_id="ip:1.1.1.1",
            relationship_type="communicated_with",
            target_entity_id="ip:8.8.8.8"
        )
        self.assertEqual(rel.confidence, 1.0)
        self.assertEqual(rel.source_entity_id, "ip:1.1.1.1")

    def test_confidence_bounds(self):
        with self.assertRaises(ValueError):
            Relationship(
                relationship_id="rel-002",
                source_entity_id="a:b",
                relationship_type="rel",
                target_entity_id="c:d",
                confidence=1.5
            )
        
        with self.assertRaises(ValueError):
            Relationship(
                relationship_id="rel-003",
                source_entity_id="a:b",
                relationship_type="rel",
                target_entity_id="c:d",
                confidence=-0.1
            )

    def test_timeline_event_creation(self):
        evt = TimelineEvent(
            event_id="evt-1",
            timestamp=datetime.now(timezone.utc),
            event_type="network",
            description="test event"
        )
        self.assertEqual(evt.event_id, "evt-1")
        
        with self.assertRaises(ValueError):
            # Pass a string instead of a datetime object
            TimelineEvent(
                event_id="evt-2",
                timestamp="2026-08-15T10:00:00Z",
                event_type="network",
                description="test event"
            )

    def test_finding_reference_creation(self):
        f = FindingReference(
            finding_id="f-001",
            finding_type="beaconing",
            severity="high",
            confidence_score=0.9
        )
        self.assertEqual(f.finding_id, "f-001")
        
        with self.assertRaises(ValueError):
            FindingReference(finding_id="", finding_type="beaconing", severity="high", confidence_score=0.9)
            
        with self.assertRaises(ValueError):
            FindingReference(finding_id="f-002", finding_type="beaconing", severity="high", confidence_score=1.1)

    def test_evidence_reference_dns_type(self):
        ev = EvidenceReference(evidence_id="ev-001", evidence_type="dns")
        self.assertEqual(ev.evidence_type, "dns")

    def test_evidence_reference_log_type(self):
        ev = EvidenceReference(evidence_id="ev-002", evidence_type="log")
        self.assertEqual(ev.evidence_type, "log")

    def test_evidence_reference_invalid_type(self):
        with self.assertRaises(ValueError):
            EvidenceReference(evidence_id="ev-003", evidence_type="unknown")

    def test_investigation_context(self):
        ctx = InvestigationContext(acquisition_id="acq-1")
        
        ent = Entity(entity_id="ip:10.0.0.1", entity_type="ip", value="10.0.0.1")
        rel = Relationship(relationship_id="r-1", source_entity_id="a:b", relationship_type="t", target_entity_id="c:d")
        evt = TimelineEvent(event_id="e-1", timestamp=datetime.now(timezone.utc), event_type="t", description="d")
        f = FindingReference(finding_id="f-1", finding_type="t", severity="high", confidence_score=0.5)
        ev = EvidenceReference(evidence_id="ev-1", evidence_type="flow")
        
        ctx.entities.append(ent)
        ctx.relationships.append(rel)
        ctx.timeline_events.append(evt)
        ctx.findings.append(f)
        ctx.evidence_references.append(ev)
        
        self.assertEqual(len(ctx.entities), 1)
        self.assertEqual(len(ctx.relationships), 1)
        self.assertEqual(len(ctx.timeline_events), 1)
        self.assertEqual(len(ctx.findings), 1)
        self.assertEqual(len(ctx.evidence_references), 1)

    def test_timeline_event_timezone_aware(self):
        from datetime import timezone, timedelta
        evt_utc = TimelineEvent(event_id="e1", timestamp=datetime.now(timezone.utc), event_type="t", description="d")
        self.assertEqual(evt_utc.timestamp.tzinfo, timezone.utc)
        
        custom_tz = timezone(timedelta(hours=5))
        evt_custom = TimelineEvent(event_id="e2", timestamp=datetime.now(custom_tz), event_type="t", description="d")
        self.assertIsNotNone(evt_custom.timestamp.tzinfo)
        
        with self.assertRaises(ValueError) as cm:
            TimelineEvent(event_id="e3", timestamp=datetime.now(), event_type="t", description="d")
        self.assertIn("timezone-aware", str(cm.exception))

    def test_investigation_context_entity_temporal_merge(self):
        from datetime import timezone
        ctx = InvestigationContext()
        
        t1 = datetime(2026, 8, 15, 18, 30, tzinfo=timezone.utc)
        t2 = datetime(2026, 8, 15, 18, 35, tzinfo=timezone.utc)
        t3 = datetime(2026, 8, 15, 18, 32, tzinfo=timezone.utc)
        
        ent_obs1 = Entity(entity_id="ip:203.0.113.10", entity_type="ip", value="203.0.113.10", first_seen=t1, last_seen=t1)
        ent_obs2 = Entity(entity_id="ip:203.0.113.10", entity_type="ip", value="203.0.113.10", first_seen=t2, last_seen=t2)
        ent_obs3 = Entity(entity_id="ip:203.0.113.10", entity_type="ip", value="203.0.113.10", first_seen=t3, last_seen=t3)
        
        ctx.add_entity(ent_obs1)
        ctx.add_entity(ent_obs2)
        ctx.add_entity(ent_obs3)
        
        self.assertEqual(len(ctx.entities), 1)
        merged_ent = ctx.entities[0]
        self.assertEqual(merged_ent.first_seen, t1)
        self.assertEqual(merged_ent.last_seen, t2)
