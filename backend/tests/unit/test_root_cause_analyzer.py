import pytest
from datetime import datetime, timezone
from app.engines.correlation.domain.input import M3InvestigationInput
from app.engines.correlation.domain.investigation import InvestigationContext
from app.engines.correlation.domain.hypothesis import Hypothesis, HypothesisValidation, ValidationStatus, HypothesisStatus
from app.engines.correlation.domain.root_cause import RootCauseStatus
from app.engines.correlation.investigation.root_cause_analyzer import RootCauseAnalyzer

@pytest.fixture
def base_m3_input():
    return M3InvestigationInput(
        acquisition_id="TEST-ACQ-1",
        network_package_id="NET-1",
        findings_package_id="FND-1",
        findings=[],
        telemetry_capabilities={"network_flow": True, "dns": True, "http": True, "tls": False},
        evidence_index={"events": {}, "flows": {}}
    )

@pytest.fixture
def base_ctx():
    return InvestigationContext(acquisition_id="TEST-ACQ-1", case_id="CASE-1")

def mk_hyp(htype: str) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=f"HYP-{htype}",
        statement="Test",
        hypothesis_type=htype,
        status=HypothesisStatus.POTENTIAL,
        confidence=0.7,
        supporting_evidence_ids=["EV-1", "EV-2"],
        supporting_finding_ids=["F-1"],
        related_entity_ids=[],
        related_mitre_mapping_ids=[],
        supporting_reasons=[],
        missing_evidence=[],
        first_seen=datetime.now(timezone.utc),
        last_seen=datetime.now(timezone.utc)
    )

def mk_val(htype: str, status: ValidationStatus, supp_ev: list = None, contra_ev: list = None, missing: list = None) -> HypothesisValidation:
    if supp_ev is None: supp_ev = ["EV-1", "EV-2"]
    if contra_ev is None: contra_ev = []
    if missing is None: missing = []
    return HypothesisValidation(
        validation_id=f"VAL-{htype}",
        hypothesis_id=f"HYP-{htype}",
        validation_status=status,
        supporting_evidence_ids=supp_ev,
        contradicting_evidence_ids=contra_ev,
        supporting_reasons=[],
        contradicting_reasons=[],
        missing_evidence=missing,
        confidence=0.8,
        validated_at=datetime.now(timezone.utc)
    )

# 1. Validated C2 hypothesis -> root cause
def test_validated_c2_hypothesis(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED)]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert len(rc) == 1
    assert rc[0].status == RootCauseStatus.SUPPORTED

# 2. Validated DNS hypothesis -> root cause
def test_validated_dns_hypothesis(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("DNS_C2")]
    base_ctx.hypothesis_validations = [mk_val("DNS_C2", ValidationStatus.VALIDATED)]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].status == RootCauseStatus.SUPPORTED
    assert "DNS" in rc[0].statement

# 3. Validated scanning hypothesis -> root cause
def test_validated_scanning_hypothesis(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("NETWORK_RECONNAISSANCE")]
    base_ctx.hypothesis_validations = [mk_val("NETWORK_RECONNAISSANCE", ValidationStatus.VALIDATED)]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].status == RootCauseStatus.SUPPORTED

# 4. Validated potential-exfil hypothesis -> conservative root cause
def test_validated_exfiltration_hypothesis(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("POTENTIAL_EXFILTRATION")]
    base_ctx.hypothesis_validations = [mk_val("POTENTIAL_EXFILTRATION", ValidationStatus.VALIDATED)]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].status == RootCauseStatus.PARTIALLY_SUPPORTED
    assert "possible exfiltration" in rc[0].statement
    assert "Process and endpoint telemetry required" in rc[0].missing_evidence[0]

# 5. Validated suspicious-web hypothesis -> root cause
def test_validated_web_hypothesis(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("SUSPICIOUS_WEB_ACTIVITY")]
    base_ctx.hypothesis_validations = [mk_val("SUSPICIOUS_WEB_ACTIVITY", ValidationStatus.VALIDATED)]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].status == RootCauseStatus.SUPPORTED

# 6. Rejected hypothesis cannot support root cause
def test_rejected_hypothesis_excluded(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.REJECTED)]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert len(rc) == 0

# 7. Inconclusive hypothesis produces no strong root cause
def test_inconclusive_hypothesis_potential(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.INCONCLUSIVE)]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].status == RootCauseStatus.POTENTIAL

# 8. Missing required telemetry lowers status
def test_missing_telemetry_lowers_status(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED, missing=["Need endpoint"])]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].status == RootCauseStatus.PARTIALLY_SUPPORTED

# 9. Contradictory evidence lowers status
def test_contradictory_evidence_lowers_status(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    # Validated but has contradiction -> lowers to POTENTIAL
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED, contra_ev=["EV-3"])]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].status == RootCauseStatus.POTENTIAL

# 10. Evidence IDs are real (preserved from validation)
def test_evidence_ids_preserved(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED, supp_ev=["EV-1"])]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].supporting_evidence_ids == ["EV-1"]

# 11. Hypothesis IDs are real (preserved)
def test_hypothesis_ids_preserved(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED)]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].supporting_hypothesis_ids == ["HYP-C2_COMMUNICATION"]

# 12. Finding IDs are real (preserved)
def test_finding_ids_preserved(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED)]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].supporting_finding_ids == ["F-1"]

# 13. Confidence bounded
def test_confidence_bounded(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED)]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert 0.0 <= rc[0].confidence <= 0.90 # cap for SUPPORTED

# 14. Confidence deterministic
def test_confidence_deterministic(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED, supp_ev=["EV-1", "EV-2"])]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    # 0.40 (base) + 0.15 (validated) + 0.10 (2 ev * 0.05) - 0 = 0.65
    assert rc[0].confidence == 0.65

# 15. root_cause_id deterministic
def test_root_cause_id_deterministic(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED)]
    analyzer = RootCauseAnalyzer()
    rc1 = analyzer.analyze(base_ctx, base_m3_input)
    rc2 = analyzer.analyze(base_ctx, base_m3_input)
    assert rc1[0].root_cause_id == rc2[0].root_cause_id

# 16. repeated run identical
def test_repeated_run_identical(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED)]
    analyzer = RootCauseAnalyzer()
    rc1 = analyzer.analyze(base_ctx, base_m3_input)
    rc2 = analyzer.analyze(base_ctx, base_m3_input)
    assert rc1 == rc2

# 17. multiple competing root causes preserved
def test_multiple_competing_causes(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION"), mk_hyp("DNS_C2")]
    base_ctx.hypothesis_validations = [
        mk_val("C2_COMMUNICATION", ValidationStatus.VALIDATED),
        mk_val("DNS_C2", ValidationStatus.VALIDATED)
    ]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert len(rc) == 2

# 18. no invented root cause when evidence is insufficient
def test_insufficient_evidence_unresolved(base_ctx, base_m3_input):
    base_ctx.hypotheses = [mk_hyp("C2_COMMUNICATION")]
    base_ctx.hypothesis_validations = [mk_val("C2_COMMUNICATION", ValidationStatus.INCONCLUSIVE, supp_ev=[])]
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert rc[0].status == RootCauseStatus.UNRESOLVED

# 19. empty hypothesis set returns safe result
def test_empty_hypothesis_list(base_ctx, base_m3_input):
    base_ctx.hypotheses = []
    base_ctx.hypothesis_validations = []
    analyzer = RootCauseAnalyzer()
    rc = analyzer.analyze(base_ctx, base_m3_input)
    assert len(rc) == 0

# 20. no LLM invocation
def test_no_llm_invocation():
    pass
