import pytest
from datetime import datetime, timezone
from app.engines.correlation.domain.input import M3InvestigationInput, EvidenceIndex
from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.timeline import TimelineEvent
from app.engines.correlation.mitre.models import MitreMapping, MappingStatus
from app.engines.correlation.domain.finding import FindingReference
from app.contracts.analysis import Finding
from app.engines.correlation.investigation.hypothesis_generator import HypothesisGenerator
from app.engines.correlation.investigation.hypothesis_validator import HypothesisValidator
from app.engines.correlation.investigation.root_cause_analyzer import RootCauseAnalyzer
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from app.shared.contract_validation import ContractValidator

def test_full_pipeline_root_cause_analysis():
    """
    Test the root cause analysis integration into the actual pipeline logic.
    M1 -> M2 -> M3Input -> Correlation -> MITRE -> HypothesisGenerator -> HypothesisValidator -> RootCauseAnalyzer -> Context -> CaseBuilder -> JSON
    """
    prov = {"acquisition_id": "TEST-ACQ-1", "source": "test", "source_log": "test"}
    ev_index = EvidenceIndex(
        events={
            "EV-HTTP": {"event_id": "EV-HTTP", "event_type": "http", "timestamp": datetime.now(timezone.utc), "source_ip": "10.0.0.1", "destination_ip": "1.1.1.1", "protocol": "http", "flow_id": "f1", "zeek_uid": "z1", "acquisition_id": "TEST-ACQ-1", "protocol_data": {}, "provenance": prov},
            "EV-HTTP2": {"event_id": "EV-HTTP2", "event_type": "http", "timestamp": datetime.now(timezone.utc), "source_ip": "10.0.0.1", "destination_ip": "2.2.2.2", "protocol": "http", "flow_id": "f2", "zeek_uid": "z2", "acquisition_id": "TEST-ACQ-1", "protocol_data": {}, "provenance": prov}
        }
    )

    findings = [
        {"finding_id": "F-WEB", "acquisition_id": "TEST-ACQ-1", "activity_class": "SUSPICIOUS_WEB_ACTIVITY", "anomaly_score": 0.5, "anomaly_detected": True, "classification_confidence": 0.9, "risk_score": 0.8, "evidence_references": [{"event_ids": ["EV-HTTP", "EV-HTTP2"], "rationale": "test"}], "model_version": "1.0"}
    ]

    m3_input = M3InvestigationInput(
        acquisition_id="ACQ-INT-02",
        network_package_id="NET-1",
        findings_package_id="FND-1",
        findings=findings,
        telemetry_capabilities={"network_flow": True, "dns": True, "http": True, "tls": False},
        evidence_index=ev_index
    )

    ctx = InvestigationContext(acquisition_id="ACQ-INT-02", case_id="CASE-INT-02")
    t1 = datetime.now(timezone.utc)
    ctx.timeline_events.append(TimelineEvent(
        event_id="TE-INT-1", timestamp=t1, event_type="network", description="Test event", entity_ids=["E-INT-1"], evidence_ids=["EV-HTTP"]
    ))
    ctx.findings = [FindingReference(finding_id="F-WEB", finding_type="finding", severity="high", confidence_score=0.9)]
    from app.engines.correlation.domain.evidence import EvidenceReference
    ctx.evidence_references = [
        EvidenceReference(evidence_id="EV-HTTP", evidence_type="http"),
        EvidenceReference(evidence_id="EV-HTTP2", evidence_type="http")
    ]

    ctx.mitre_mappings = [
        MitreMapping(
            mapping_id="M-INT-1",
            behavior_id="B-INT-1",
            technique_id="T1071.001",
            technique_name="Web Protocols",
            finding_id="F-WEB",
            mapping_status=MappingStatus.SUPPORTED,
            mapping_confidence=0.9,
            rationale="Test int",
            knowledge_profile_id="KP-1",
            mitre_version="1.0",
            evidence_ids=["EV-HTTP"]
        )
    ]

    # Generator
    gen = HypothesisGenerator()
    ctx.hypotheses = gen.generate(ctx, m3_input)
    assert len(ctx.hypotheses) == 1

    # Validator
    val = HypothesisValidator()
    ctx.hypothesis_validations = val.validate(ctx, m3_input)
    assert len(ctx.hypothesis_validations) == 1
    assert ctx.hypothesis_validations[0].validation_status.value == "VALIDATED"

    # Analyzer
    rca = RootCauseAnalyzer()
    ctx.root_causes = rca.analyze(ctx, m3_input)

    assert len(ctx.root_causes) == 1
    assert ctx.root_causes[0].status.value == "SUPPORTED"
    assert "web-protocol use" in ctx.root_causes[0].statement
    assert ctx.root_causes[0].supporting_evidence_ids == ["EV-HTTP", "EV-HTTP2"]

    # CaseBuilder Validation
    c_val = ContractValidator()
    builder = InvestigationCaseBuilder(c_val)
    doc = builder.build(ctx)

    assert doc["schema_version"] == "investigation-case-v1.3"
    assert len(doc["assessment"]["root_causes"]) == 1
    
    rc_doc = doc["assessment"]["root_causes"][0]
    assert rc_doc["status"] == "SUPPORTED"
    assert "EV-HTTP" in rc_doc["supporting_evidence_ids"]
    assert rc_doc["supporting_hypothesis_ids"] == [doc["assessment"]["hypotheses"][0]["hypothesis_id"]]
    assert len(rc_doc["root_cause_id"]) == 15 # "RC-" + 12
