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
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from app.shared.contract_validation import ContractValidator

def test_full_pipeline_hypothesis_validation():
    """
    Test the hypothesis validation integration into the actual pipeline logic.
    M1 -> M2 -> M3Input -> Correlation -> MITRE -> HypothesisGenerator -> HypothesisValidator -> Context -> CaseBuilder -> JSON
    """
    # 1. Setup M1/M2/M3 Input
    prov = {"acquisition_id": "TEST-ACQ-1", "source": "test", "source_log": "test"}
    ev_index = EvidenceIndex(
        events={
            "EV-HTTP": {"event_id": "EV-HTTP", "event_type": "http", "timestamp": datetime.now(timezone.utc), "source_ip": "10.0.0.1", "destination_ip": "1.1.1.1", "protocol": "http", "flow_id": "f1", "zeek_uid": "z1", "acquisition_id": "TEST-ACQ-1", "protocol_data": {}, "provenance": prov}
        }
    )

    findings = [
        {"finding_id": "F-WEB", "acquisition_id": "TEST-ACQ-1", "activity_class": "SUSPICIOUS_WEB_ACTIVITY", "anomaly_score": 0.5, "anomaly_detected": True, "classification_confidence": 0.9, "risk_score": 0.8, "evidence_references": [{"event_ids": ["EV-HTTP"], "rationale": "test"}], "model_version": "1.0"}
    ]

    m3_input = M3InvestigationInput(
        acquisition_id="ACQ-INT-01",
        network_package_id="NET-1",
        findings_package_id="FND-1",
        findings=findings,
        telemetry_capabilities={"network_flow": True, "dns": True, "http": True, "tls": False},
        evidence_index=ev_index
    )

    # 2. Setup Context
    ctx = InvestigationContext(acquisition_id="ACQ-INT-01", case_id="CASE-INT-01")
    t1 = datetime.now(timezone.utc)
    ctx.timeline_events.append(TimelineEvent(
        event_id="TE-INT-1", timestamp=t1, event_type="network", description="Test event", entity_ids=["E-INT-1"], evidence_ids=["EV-HTTP"]
    ))
    ctx.findings = [FindingReference(finding_id="F-WEB", finding_type="finding", severity="high", confidence_score=0.9)]
    # Setup evidence reference so CaseBuilder validation passes
    from app.engines.correlation.domain.evidence import EvidenceReference
    ctx.evidence_references = [EvidenceReference(evidence_id="EV-HTTP", evidence_type="http")]

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

    # 3. Execute Generator
    gen = HypothesisGenerator()
    ctx.hypotheses = gen.generate(ctx, m3_input)
    assert len(ctx.hypotheses) == 1

    # 4. Execute Validator
    validator = HypothesisValidator()
    ctx.hypothesis_validations = validator.validate(ctx, m3_input)

    assert len(ctx.hypothesis_validations) == 1
    assert ctx.hypothesis_validations[0].validation_status.value == "VALIDATED"
    assert "EV-HTTP" in ctx.hypothesis_validations[0].supporting_evidence_ids

    # 5. CaseBuilder Validation
    c_val = ContractValidator()
    builder = InvestigationCaseBuilder(c_val)
    doc = builder.build(ctx)

    assert doc["schema_version"] == "investigation-case-v1.3"
    assert len(doc["assessment"]["hypotheses"]) == 1
    assert len(doc["assessment"]["hypothesis_validations"]) == 1
    
    val_doc = doc["assessment"]["hypothesis_validations"][0]
    assert val_doc["validation_status"] == "VALIDATED"
    assert "EV-HTTP" in val_doc["supporting_evidence_ids"]
    assert val_doc["hypothesis_id"] == doc["assessment"]["hypotheses"][0]["hypothesis_id"]
    
    # Verify deterministic output (hash length 12)
    assert len(val_doc["validation_id"]) == 16 # "VAL-" + 12
