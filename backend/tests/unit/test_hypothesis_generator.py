import pytest
from datetime import datetime, timezone

from app.engines.correlation.domain.input import M3InvestigationInput, EvidenceIndex
from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.finding import FindingReference
from app.engines.correlation.domain.evidence import EvidenceReference
from app.engines.correlation.domain.timeline import TimelineEvent
from app.engines.correlation.investigation.hypothesis_generator import HypothesisGenerator
from app.engines.correlation.mitre.models import MitreMapping
from app.contracts.analysis import Finding
from app.contracts.network_intelligence import ProtocolEvent, Flow

@pytest.fixture
def base_m3_input():
    prov = {"acquisition_id": "TEST-ACQ-1", "source": "test", "source_log": "test"}
    ev_index = EvidenceIndex(
        events={
            "EV-DNS": {"event_id": "EV-DNS", "event_type": "dns", "timestamp": datetime.now(timezone.utc), "source_ip": "10.0.0.1", "destination_ip": "8.8.8.8", "protocol": "dns", "flow_id": "f1", "zeek_uid": "z1", "acquisition_id": "TEST-ACQ-1", "protocol_data": {}, "provenance": prov},
            "EV-HTTP": {"event_id": "EV-HTTP", "event_type": "http", "timestamp": datetime.now(timezone.utc), "source_ip": "10.0.0.1", "destination_ip": "1.1.1.1", "protocol": "http", "flow_id": "f2", "zeek_uid": "z2", "acquisition_id": "TEST-ACQ-1", "protocol_data": {}, "provenance": prov}
        },
        flows={
            "EV-FLOW": {"flow_id": "EV-FLOW", "source": {"ip": "10.0.0.1", "port": 1234}, "destination": {"ip": "1.1.1.1", "port": 80}, "protocol": "tcp", "bytes_in": 100, "bytes_out": 100000, "timestamp": datetime.now(timezone.utc), "duration": 1.0, "acquisition_id": "TEST-ACQ-1", "zeek_uid": "z3", "provenance": prov}
        }
    )
    
    def mk(fid, ac, ev):
        return {"finding_id": fid, "acquisition_id": "TEST-ACQ-1", "activity_class": ac, "anomaly_score": 0.5, "anomaly_detected": True, "classification_confidence": 0.9, "risk_score": 0.8, "evidence_references": [{"event_ids": [ev] if "DNS" in ev or "HTTP" in ev else [], "flow_ids": [ev] if "FLOW" in ev else [], "rationale": "test"}], "model_version": "1.0"}

    findings = [
        mk("F-C2", "C2_MALWARE_COMMUNICATION", "EV-FLOW"),
        mk("F-DNS", "DNS_ANOMALY_TUNNELING", "EV-DNS"),
        mk("F-SCAN", "SCANNING_RECONNAISSANCE", "EV-FLOW"),
        mk("F-EXFIL", "POSSIBLE_EXFILTRATION", "EV-FLOW"),
        mk("F-WEB", "SUSPICIOUS_WEB_ACTIVITY", "EV-HTTP"),
        mk("F-BOGUS", "BENIGN", "EV-FLOW")
    ]
    
    return M3InvestigationInput(
        acquisition_id="TEST-ACQ-1",
        network_package_id="NET-1",
        findings_package_id="FND-1",
        findings=findings,
        telemetry_capabilities={"network_flow": True, "dns": True, "http": True, "tls": False},
        evidence_index=ev_index
    )

@pytest.fixture
def base_ctx():
    ctx = InvestigationContext(acquisition_id="TEST-ACQ-1", case_id="CASE-1")
    t1 = datetime.now(timezone.utc)
    ctx.timeline_events.append(TimelineEvent(event_id="TE-1", timestamp=t1, event_type="network", description="Test", entity_ids=["E-1"], evidence_ids=["EV-DNS", "EV-HTTP", "EV-FLOW"]))
    
    # Adding finding references
    ctx.findings = [
        FindingReference(finding_id="F-C2", finding_type="finding", severity="high", confidence_score=0.9),
        FindingReference(finding_id="F-DNS", finding_type="finding", severity="high", confidence_score=0.9),
        FindingReference(finding_id="F-SCAN", finding_type="finding", severity="high", confidence_score=0.9),
        FindingReference(finding_id="F-EXFIL", finding_type="finding", severity="high", confidence_score=0.9),
        FindingReference(finding_id="F-WEB", finding_type="finding", severity="high", confidence_score=0.9)
    ]
    
    # Add mitre mapping
    from app.engines.correlation.mitre.models import MappingStatus
    ctx.mitre_mappings = [
        MitreMapping(
            mapping_id="M-1",
            behavior_id="B-1",
            technique_id="T1071", 
            technique_name="Application Layer Protocol", 
            finding_id="F-C2",
            mapping_status=MappingStatus.SUPPORTED,
            mapping_confidence=0.9,
            rationale="Test",
            knowledge_profile_id="KP-1",
            mitre_version="1.0"
        )
    ]
    return ctx

def test_c2_generates_c2_hypothesis(base_ctx, base_m3_input):
    base_ctx.findings = [FindingReference(finding_id="F-C2", finding_type="finding", severity="high", confidence_score=0.9)]
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 1
    assert hyps[0].hypothesis_type == "C2_COMMUNICATION"

def test_dns_generates_dns_hypothesis(base_ctx, base_m3_input):
    base_ctx.findings = [FindingReference(finding_id="F-DNS", finding_type="finding", severity="high", confidence_score=0.9)]
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 1
    assert hyps[0].hypothesis_type == "DNS_C2"

def test_scanning_generates_recon_hypothesis(base_ctx, base_m3_input):
    base_ctx.findings = [FindingReference(finding_id="F-SCAN", finding_type="finding", severity="high", confidence_score=0.9)]
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 1
    assert hyps[0].hypothesis_type == "NETWORK_RECONNAISSANCE"

def test_exfil_generates_potential_exfil_hypothesis(base_ctx, base_m3_input):
    base_ctx.findings = [FindingReference(finding_id="F-EXFIL", finding_type="finding", severity="high", confidence_score=0.9)]
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 1
    assert hyps[0].hypothesis_type == "POTENTIAL_EXFILTRATION"
    assert "Endpoint process context" in hyps[0].missing_evidence[0]

def test_suspicious_web_generates_web_hypothesis(base_ctx, base_m3_input):
    base_ctx.findings = [FindingReference(finding_id="F-WEB", finding_type="finding", severity="high", confidence_score=0.9)]
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 1
    assert hyps[0].hypothesis_type == "SUSPICIOUS_WEB_ACTIVITY"

def test_missing_dns_evidence_prevents_dns_hypothesis(base_ctx, base_m3_input):
    base_ctx.findings = [FindingReference(finding_id="F-DNS", finding_type="finding", severity="high", confidence_score=0.9)]
    # Remove DNS evidence from the finding
    base_m3_input = base_m3_input.model_copy(update={"findings": [Finding(**{"finding_id": "F-DNS", "acquisition_id": "TEST-ACQ-1", "activity_class": "DNS_ANOMALY_TUNNELING", "anomaly_score": 0.5, "anomaly_detected": True, "classification_confidence": 0.9, "risk_score": 0.8, "evidence_references": [{"event_ids": ["EV-FLOW"], "rationale": "test"}], "model_version": "1.0"})]})
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 0

def test_missing_http_evidence_prevents_web_hypothesis(base_ctx, base_m3_input):
    base_ctx.findings = [FindingReference(finding_id="F-WEB", finding_type="finding", severity="high", confidence_score=0.9)]
    base_m3_input = base_m3_input.model_copy(update={"findings": [Finding(**{"finding_id": "F-WEB", "acquisition_id": "TEST-ACQ-1", "activity_class": "SUSPICIOUS_WEB_ACTIVITY", "anomaly_score": 0.5, "anomaly_detected": True, "classification_confidence": 0.9, "risk_score": 0.8, "evidence_references": [{"event_ids": ["EV-DNS"], "rationale": "test"}], "model_version": "1.0"})]})
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 0

def test_missing_evidence_prevents_all_hypotheses(base_ctx, base_m3_input):
    base_ctx.findings = [FindingReference(finding_id="F-C2", finding_type="finding", severity="high", confidence_score=0.9)]
    base_m3_input = base_m3_input.model_copy(update={"findings": [Finding(**{"finding_id": "F-C2", "acquisition_id": "TEST-ACQ-1", "activity_class": "C2_MALWARE_COMMUNICATION", "anomaly_score": 0.5, "anomaly_detected": True, "classification_confidence": 0.9, "risk_score": 0.8, "evidence_references": [{"event_ids": ["EV-NONEXISTENT"], "rationale": "test"}], "model_version": "1.0"})]})
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 0

def test_no_unsupported_confirmation(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    for h in hyps:
        assert h.status.value == "POTENTIAL"
        assert "Confirmed" not in h.statement

def test_evidence_ids_are_real(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    for h in hyps:
        for ev in h.supporting_evidence_ids:
            assert ev in base_m3_input.evidence_index.flows or ev in base_m3_input.evidence_index.events

def test_finding_ids_are_real(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    for h in hyps:
        for f in h.supporting_finding_ids:
            assert f in [x.finding_id for x in base_m3_input.findings]

def test_mitre_mapping_ids_are_real(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    for h in hyps:
        for m in h.related_mitre_mapping_ids:
            assert m in [x.technique_id for x in base_ctx.mitre_mappings]

def test_related_entities_are_real(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    for h in hyps:
        for e in h.related_entity_ids:
            assert e == "E-1"

def test_first_seen_last_seen_deterministic(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    for h in hyps:
        assert h.first_seen is not None
        assert h.last_seen is not None
        assert h.first_seen == h.last_seen == base_ctx.timeline_events[0].timestamp

def test_confidence_bounded(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    for h in hyps:
        assert 0.0 <= h.confidence <= 1.0

def test_confidence_deterministic(base_ctx, base_m3_input):
    base_ctx.findings = [FindingReference(finding_id="F-C2", finding_type="finding", severity="high", confidence_score=0.9)]
    # Base 0.5 + 0.1 (entity) + 0.1 (mitre) = 0.7
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert hyps[0].confidence == 0.7

def test_hypothesis_id_deterministic(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    h1 = gen.generate(base_ctx, base_m3_input)
    h2 = gen.generate(base_ctx, base_m3_input)
    for a, b in zip(h1, h2):
        assert a.hypothesis_id == b.hypothesis_id

def test_repeated_execution_produces_identical_output(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    h1 = gen.generate(base_ctx, base_m3_input)
    h2 = gen.generate(base_ctx, base_m3_input)
    assert h1 == h2

def test_duplicate_evidence_does_not_duplicate_hypotheses(base_ctx, base_m3_input):
    base_ctx.findings = [
        FindingReference(finding_id="F-C2", finding_type="finding", severity="high", confidence_score=0.9),
        FindingReference(finding_id="F-C2", finding_type="finding", severity="high", confidence_score=0.9) # Duplicate ref
    ]
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 1

def test_unrelated_finding_does_not_generate_hypothesis(base_ctx, base_m3_input):
    base_ctx.findings = [FindingReference(finding_id="F-BOGUS", finding_type="finding", severity="high", confidence_score=0.9)]
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 0

def test_all_five_families_can_coexist(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    hyps = gen.generate(base_ctx, base_m3_input)
    assert len(hyps) == 5

def test_empty_context_produces_empty(base_m3_input):
    ctx = InvestigationContext(acquisition_id="TEST-ACQ-1", case_id="CASE-1")
    gen = HypothesisGenerator()
    assert len(gen.generate(ctx, base_m3_input)) == 0

# 25. existing CaseBuilder serializes generated hypotheses into V1.3.
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from app.shared.contract_validation import ContractValidator

def test_existing_casebuilder_serializes_generated_hypotheses_into_v1_3(base_ctx, base_m3_input):
    gen = HypothesisGenerator()
    base_ctx.hypotheses = gen.generate(base_ctx, base_m3_input)
    
    # We must also ensure declared evidence exists for case builder referential integrity
    base_ctx.evidence_references = [
        EvidenceReference(evidence_id="EV-DNS", evidence_type="dns"),
        EvidenceReference(evidence_id="EV-HTTP", evidence_type="http"),
        EvidenceReference(evidence_id="EV-FLOW", evidence_type="flow")
    ]
    
    validator = ContractValidator()
    builder = InvestigationCaseBuilder(validator)
    
    doc = builder.build(base_ctx)
    assert doc["schema_version"] == "investigation-case-v1.3"
    assert len(doc["assessment"]["hypotheses"]) == 5
    types = [h["hypothesis_type"] for h in doc["assessment"]["hypotheses"]]
    assert "C2_COMMUNICATION" in types
