"""
reports.py
----------
M2 Phase 9 — Evaluation Reports Generator.

Generates unified M2 Evaluation Reports combining unsupervised metrics, supervised metrics,
threshold configuration, performance benchmarks, and validation check statuses.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from app.engines.analysis.evaluation.metrics import (
    PerformanceMetrics,
    SupervisedEvaluationMetrics,
    UnsupervisedEvaluationMetrics,
)
from app.engines.analysis.evaluation.threshold_optimizer import ThresholdConfig

logger = logging.getLogger(__name__)


class M2EvaluationReport(BaseModel):
    """Unified evaluation report for M2 Phase 9 Production Validation."""

    report_id: str = Field(
        default_factory=lambda: f"ER-{uuid4().hex[:12].upper()}",
        description="Unique evaluation report identifier",
    )
    generated_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when report was generated",
    )
    unsupervised_metrics: UnsupervisedEvaluationMetrics
    supervised_metrics: SupervisedEvaluationMetrics
    threshold_config: ThresholdConfig
    performance_metrics: Optional[PerformanceMetrics] = None
    registry_id: Optional[str] = None
    validation_checks_passed: bool = Field(True)
    summary_notes: str = Field(default="")

    model_config = {"frozen": True, "extra": "forbid"}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_json(cls, json_str: str) -> "M2EvaluationReport":
        return cls.model_validate_json(json_str)


def generate_m2_evaluation_report(
    *,
    unsupervised_metrics: UnsupervisedEvaluationMetrics,
    supervised_metrics: SupervisedEvaluationMetrics,
    threshold_config: ThresholdConfig,
    performance_metrics: Optional[PerformanceMetrics] = None,
    registry_id: Optional[str] = None,
    summary_notes: str = "M2 Evaluation Completed.",
) -> M2EvaluationReport:
    """Construct an M2EvaluationReport instance."""
    validation_passed = True
    if performance_metrics:
        validation_passed = (
            performance_metrics.deterministic_pass and performance_metrics.failure_behavior_pass
        )

    return M2EvaluationReport(
        unsupervised_metrics=unsupervised_metrics,
        supervised_metrics=supervised_metrics,
        threshold_config=threshold_config,
        performance_metrics=performance_metrics,
        registry_id=registry_id,
        validation_checks_passed=validation_passed,
        summary_notes=summary_notes,
    )
