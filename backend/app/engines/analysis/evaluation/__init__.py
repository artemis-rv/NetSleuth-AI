"""
M2 Phase 9 — Evaluation, Threshold Tuning, Model Versioning, and Production Validation Package.

Exposes evaluation metrics, threshold optimizer, model registry, evaluator engine, and report generator.
"""

from app.engines.analysis.evaluation.evaluator import M2Evaluator
from app.engines.analysis.evaluation.metrics import (
    PerformanceMetrics,
    ScoreDistributionQuantiles,
    SupervisedEvaluationMetrics,
    UnsupervisedEvaluationMetrics,
    compute_supervised_metrics,
    compute_unsupervised_metrics,
)
from app.engines.analysis.evaluation.model_registry import (
    ModelRegistry,
    RegistryArtifactEntry,
)
from app.engines.analysis.evaluation.reports import (
    M2EvaluationReport,
    generate_m2_evaluation_report,
)
from app.engines.analysis.evaluation.threshold_optimizer import (
    ThresholdConfig,
    ThresholdOptimizer,
)

__all__ = [
    "M2Evaluator",
    "ThresholdOptimizer",
    "ThresholdConfig",
    "ModelRegistry",
    "RegistryArtifactEntry",
    "M2EvaluationReport",
    "generate_m2_evaluation_report",
    "compute_unsupervised_metrics",
    "compute_supervised_metrics",
    "UnsupervisedEvaluationMetrics",
    "SupervisedEvaluationMetrics",
    "PerformanceMetrics",
    "ScoreDistributionQuantiles",
]
