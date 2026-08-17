"""
M2 Phase 7 — Analysis Decision Engine Package.

Exposes decision state structures, risk scoring, confidence evaluation, and the
AnalysisDecisionEngine orchestrator.
"""

from app.engines.analysis.decision.confidence import calculate_confidence
from app.engines.analysis.decision.engine import AnalysisDecisionEngine
from app.engines.analysis.decision.result import (
    ENGINE_VERSION,
    AnalysisDecisionResult,
    DecisionState,
)
from app.engines.analysis.decision.risk import (
    ACTIVITY_SEVERITY_WEIGHTS,
    calculate_risk_score,
)

__all__ = [
    "AnalysisDecisionEngine",
    "AnalysisDecisionResult",
    "DecisionState",
    "calculate_confidence",
    "calculate_risk_score",
    "ACTIVITY_SEVERITY_WEIGHTS",
    "ENGINE_VERSION",
]
