import pytest
import copy
from datetime import datetime, timezone
from jsonschema.exceptions import ValidationError

from app.shared.contract_validation import ContractValidator
from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.evidence import EvidenceReference
from app.engines.correlation.domain.timeline import TimelineEvent
from app.engines.correlation.domain.hypothesis import Hypothesis, HypothesisStatus, HypothesisValidation, ValidationStatus
from app.engines.correlation.domain.root_cause import RootCause, RootCauseStatus
from app.engines.correlation.domain.impact import ImpactAssessment, ImpactStatus
from app.engines.correlation.investigation.case_builder import InvestigationCaseBuilder

@pytest.fixture
def validator():
    return ContractValidator()

@pytest.fixture
def base_context():
    ctx = InvestigationContext(acquisition_id="TEST-01")
    ctx.evidence_references.append(
        EvidenceReference(evidence_id="EV-1", evidence_type="pcap")
    )
    ctx.timeline_events.append(
        TimelineEvent(event_id="TEV-1", timestamp=datetime.now(timezone.utc), event_type="network", description="Test event", evidence_ids=["EV-1"])
    )
    return ctx

def test_v1_2_still_validates(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    doc = builder.build(base_context)
    assert doc["schema_version"] == "investigation-case-v1.2"
    assert "assessment" not in doc or "hypotheses" not in doc.get("assessment", {})

def test_v1_3_new_collections_default_empty():
    ctx = InvestigationContext()
    assert ctx.hypotheses == []
    assert ctx.hypothesis_validations == []
    assert ctx.root_causes == []
    assert ctx.impact_assessments == []

def test_valid_v1_3_case_no_hypotheses(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    # Trigger V1.3 by adding an empty impact, but actually if we just add one it's enough.
    # We need to test the condition.
    base_context.impact_assessments.append(ImpactAssessment(
        impact_id="IMP-1", category="TEST", statement="Impact", status=ImpactStatus.OBSERVED,
        confidence=1.0, supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    assert doc["schema_version"] == "investigation-case-v1.3"
    assert doc["assessment"]["impact_assessments"][0]["impact_id"] == "IMP-1"

def test_valid_v1_3_with_hypotheses(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.hypotheses.append(Hypothesis(
        hypothesis_id="HYP-1", statement="Test hyp", hypothesis_type="TEST",
        status=HypothesisStatus.POTENTIAL, confidence=0.8, supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    assert doc["schema_version"] == "investigation-case-v1.3"
    assert len(doc["assessment"]["hypotheses"]) == 1

def test_invalid_hypothesis_confidence(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.hypotheses.append(Hypothesis(
        hypothesis_id="HYP-1", statement="Test hyp", hypothesis_type="TEST",
        status=HypothesisStatus.POTENTIAL, confidence=1.5, supporting_evidence_ids=["EV-1"]
    ))
    with pytest.raises(ValidationError):
        builder.build(base_context)

def test_missing_hypothesis_evidence(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.hypotheses.append(Hypothesis(
        hypothesis_id="HYP-1", statement="Test hyp", hypothesis_type="TEST",
        status=HypothesisStatus.POTENTIAL, confidence=0.8, supporting_evidence_ids=[]
    ))
    # Schema says minItems: 1
    with pytest.raises(ValidationError):
        builder.build(base_context)

def test_invalid_hypothesis_status(validator, base_context):
    # Tested by manually messing with the payload to force an invalid enum since dataclass uses Enum.
    builder = InvestigationCaseBuilder(validator)
    base_context.hypotheses.append(Hypothesis(
        hypothesis_id="HYP-1", statement="Test hyp", hypothesis_type="TEST",
        status=HypothesisStatus.POTENTIAL, confidence=0.8, supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    doc["assessment"]["hypotheses"][0]["status"] = "CONFIRMED" # not allowed in hypothesis
    with pytest.raises(ValidationError):
        validator.validate("investigation-case-v1.3.json", doc)

def test_valid_hypothesis_validation(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.hypothesis_validations.append(HypothesisValidation(
        validation_id="VAL-1", hypothesis_id="HYP-1", validation_status=ValidationStatus.VALIDATED,
        confidence=0.9, validated_at=datetime.now(timezone.utc), supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    assert doc["schema_version"] == "investigation-case-v1.3"

def test_invalid_validation_status(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    doc = builder.build(base_context)
    doc["schema_version"] = "investigation-case-v1.3"
    doc["assessment"] = {
        "hypothesis_validations": [{
            "validation_id": "V-1", "hypothesis_id": "H-1", "validation_status": "BOGUS",
            "confidence": 0.5, "validated_at": "2026-08-18T00:00:00Z"
        }]
    }
    with pytest.raises(ValidationError):
        validator.validate("investigation-case-v1.3.json", doc)

def test_validated_validation_without_evidence_fails(validator, base_context):
    # This logic wasn't in schema, so let's check it in builder.
    builder = InvestigationCaseBuilder(validator)
    base_context.hypothesis_validations.append(HypothesisValidation(
        validation_id="VAL-1", hypothesis_id="HYP-1", validation_status=ValidationStatus.VALIDATED,
        confidence=0.9, validated_at=datetime.now(timezone.utc), supporting_evidence_ids=[], contradicting_evidence_ids=[]
    ))
    # We must add a manual check in builder, or it'll pass if schema didn't block it.
    # If the check is not there, we will fail this test and then add it.
    with pytest.raises(ValueError, match="must have evidence"):
        builder.build(base_context)

def test_valid_inconclusive_validation(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.hypothesis_validations.append(HypothesisValidation(
        validation_id="VAL-1", hypothesis_id="HYP-1", validation_status=ValidationStatus.INCONCLUSIVE,
        confidence=0.9, validated_at=datetime.now(timezone.utc), missing_evidence=["Logs missing"]
    ))
    doc = builder.build(base_context)
    assert len(doc["assessment"]["hypothesis_validations"]) == 1

def test_valid_root_cause(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.root_causes.append(RootCause(
        root_cause_id="RC-1", statement="Root", status=RootCauseStatus.SUPPORTED,
        confidence=0.9, supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    assert doc["schema_version"] == "investigation-case-v1.3"

def test_root_cause_without_evidence_fails(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.root_causes.append(RootCause(
        root_cause_id="RC-1", statement="Root", status=RootCauseStatus.SUPPORTED,
        confidence=0.9, supporting_evidence_ids=[]
    ))
    with pytest.raises(ValidationError):
        builder.build(base_context)

def test_invalid_root_cause_status(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.root_causes.append(RootCause(
        root_cause_id="RC-1", statement="Root", status=RootCauseStatus.SUPPORTED,
        confidence=0.9, supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    doc["assessment"]["root_causes"][0]["status"] = "CONFIRMED" # Invalid root cause status
    with pytest.raises(ValidationError):
        validator.validate("investigation-case-v1.3.json", doc)

def test_valid_impact_assessment(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.impact_assessments.append(ImpactAssessment(
        impact_id="IMP-1", category="TEST", statement="Impact", status=ImpactStatus.OBSERVED,
        confidence=1.0, supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    assert doc["schema_version"] == "investigation-case-v1.3"

def test_impact_without_evidence_fails(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.impact_assessments.append(ImpactAssessment(
        impact_id="IMP-1", category="TEST", statement="Impact", status=ImpactStatus.OBSERVED,
        confidence=1.0, supporting_evidence_ids=[]
    ))
    with pytest.raises(ValidationError):
        builder.build(base_context)

def test_invalid_impact_status(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.impact_assessments.append(ImpactAssessment(
        impact_id="IMP-1", category="TEST", statement="Impact", status=ImpactStatus.OBSERVED,
        confidence=1.0, supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    doc["assessment"]["impact_assessments"][0]["status"] = "CONFIRMED" # Invalid impact status
    with pytest.raises(ValidationError):
        validator.validate("investigation-case-v1.3.json", doc)

def test_unknown_fields_rejected(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.hypotheses.append(Hypothesis(
        hypothesis_id="HYP-1", statement="Test hyp", hypothesis_type="TEST",
        status=HypothesisStatus.POTENTIAL, confidence=0.8, supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    doc["assessment"]["hypotheses"][0]["bogus_field"] = "bogus"
    with pytest.raises(ValidationError):
        validator.validate("investigation-case-v1.3.json", doc)

def test_v1_3_deterministic_json_round_trip(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.hypotheses.append(Hypothesis(
        hypothesis_id="HYP-1", statement="Test hyp", hypothesis_type="TEST",
        status=HypothesisStatus.POTENTIAL, confidence=0.8, supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    import json
    json_str = json.dumps(doc, sort_keys=True)
    loaded_doc = json.loads(json_str)
    assert loaded_doc == doc

def test_builder_preserves_new_fields(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.hypotheses.append(Hypothesis(
        hypothesis_id="HYP-1", statement="Test hyp", hypothesis_type="TEST",
        status=HypothesisStatus.POTENTIAL, confidence=0.8, supporting_evidence_ids=["EV-1"]
    ))
    doc = builder.build(base_context)
    assert doc["assessment"]["hypotheses"][0]["statement"] == "Test hyp"

def test_evidence_references_remain_traceable(validator, base_context):
    builder = InvestigationCaseBuilder(validator)
    base_context.hypotheses.append(Hypothesis(
        hypothesis_id="HYP-1", statement="Test hyp", hypothesis_type="TEST",
        status=HypothesisStatus.POTENTIAL, confidence=0.8, supporting_evidence_ids=["EV-BOGUS"]
    ))
    with pytest.raises(ValueError, match="references undeclared evidence ID"):
        builder.build(base_context)
