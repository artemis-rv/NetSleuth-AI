import pytest
from datetime import datetime, timezone

from app.engines.correlation.domain.input import M3InvestigationInput, EvidenceIndex
from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.finding import FindingReference
from app.engines.correlation.domain.evidence import EvidenceReference
from app.engines.correlation.domain.timeline import TimelineEvent
from app.engines.correlation.mitre.models import MitreMapping, MappingStatus
from app.contracts.analysis import Finding
from app.contracts.network_intelligence import ProtocolEvent, Flow
from app.engines.correlation.investigation.hypothesis_generator import HypothesisGenerator
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder
from app.shared.contract_validation import ContractValidator

def test_full_pipeline_hypothesis_generation():
    """
    Test the hypothesis generation integration into the actual pipeline logic.
    M1 -> M2 -> M3Input -> Correlation -> MITRE -> HypothesisGenerator -> Context -> CaseBuilder -> JSON
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
    
    # 2. Setup Context (Normally done by correlation engine)
    ctx = InvestigationContext(acquisition_id="ACQ-INT-01", case_id="CASE-INT-01")
    t1 = datetime.now(timezone.utc)
    ctx.timeline_events.append(TimelineEvent(
        event_id="TE-INT-1", timestamp=t1, event_type="network", description="Test event", entity_ids=["E-INT-1"], evidence_ids=["EV-HTTP"]
    ))
    ctx.findings = [FindingReference(finding_id="F-WEB", finding_type="finding", severity="high", confidence_score=0.9)]
    ctx.evidence_references = [EvidenceReference(evidence_id="EV-HTTP", evidence_type="http")]
    
    # MITRE Mappings (Normally done by MitreMapper)
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
    
    # 3. Execute HypothesisGenerator
    gen = HypothesisGenerator()
    hyps = gen.generate(ctx, m3_input)
    
    # Verify generation results before builder
    assert len(hyps) == 1
    hyp = hyps[0]
    assert hyp.hypothesis_type == "SUSPICIOUS_WEB_ACTIVITY"
    assert "EV-HTTP" in hyp.supporting_evidence_ids
    assert "F-WEB" in hyp.supporting_finding_ids
    assert "T1071.001" in hyp.related_mitre_mapping_ids
    
    # Inject into context
    ctx.hypotheses = hyps
    
    # 4. Execute CaseBuilder
    validator = ContractValidator()
    builder = InvestigationCaseBuilder(validator)
    
    doc = builder.build(ctx)
    
    # 5. Verify final JSON payload
    assert doc["schema_version"] == "investigation-case-v1.3"
    
    # Traceability checks
    h_doc = doc["assessment"]["hypotheses"][0]
    assert h_doc["status"] == "POTENTIAL"
    assert h_doc["confidence"] == 0.7  # 0.5 base + 0.1 entity + 0.1 mitre
    assert "EV-HTTP" in h_doc["supporting_evidence_ids"]
    assert "F-WEB" in h_doc["supporting_finding_ids"]
    assert "T1071.001" in h_doc["related_mitre_mapping_ids"]
    assert "E-INT-1" in h_doc["related_entity_ids"]
