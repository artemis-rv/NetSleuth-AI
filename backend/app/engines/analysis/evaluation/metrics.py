"""
metrics.py
----------
M2 Phase 9 — Comprehensive Evaluation Metrics.

Computes evaluation metrics for unsupervised anomaly models, supervised activity
classifiers, and end-to-end M2 performance benchmarking.
"""

from __future__ import annotations

import math
from typing import Any, Optional
import numpy as np
from pydantic import BaseModel, Field
from sklearn.metrics import (
    accuracy_score,
    auc,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)

from backend.app.contracts.analysis import ActivityClass
from backend.app.engines.analysis.dataset.labels import UNMAPPED
from backend.app.engines.analysis.models.classification.label_map import (
    ALL_ACTIVITY_CLASSES,
    map_cicids_label,
)


class ScoreDistributionQuantiles(BaseModel):
    """Statistical summary of anomaly score distributions."""

    min_score: float
    q25: float
    median: float
    q75: float
    q95: float
    q99: float
    max_score: float
    mean_score: float
    std_score: float

    model_config = {"frozen": True, "extra": "forbid"}


class UnsupervisedEvaluationMetrics(BaseModel):
    """Evaluation metrics for the unsupervised Isolation Forest model."""

    benign_fpr: float = Field(..., ge=0.0, le=1.0)
    anomaly_detection_rate: float = Field(..., ge=0.0, le=1.0)
    roc_auc: Optional[float] = Field(None, ge=0.0, le=1.0)
    pr_auc: Optional[float] = Field(None, ge=0.0, le=1.0)
    benign_distribution: ScoreDistributionQuantiles
    attack_distribution: Optional[ScoreDistributionQuantiles] = None
    per_activity_detection_rates: dict[str, float] = Field(default_factory=dict)

    model_config = {"frozen": True, "extra": "forbid"}


class SupervisedEvaluationMetrics(BaseModel):
    """Evaluation metrics for the supervised Random Forest activity model."""

    accuracy: float = Field(..., ge=0.0, le=1.0)
    balanced_accuracy: float = Field(..., ge=0.0, le=1.0)
    macro_f1: float = Field(..., ge=0.0, le=1.0)
    weighted_f1: float = Field(..., ge=0.0, le=1.0)
    per_class_precision: dict[str, float] = Field(default_factory=dict)
    per_class_recall: dict[str, float] = Field(default_factory=dict)
    per_class_f1: dict[str, float] = Field(default_factory=dict)
    confusion_matrix: list[list[int]] = Field(default_factory=list)
    class_labels: list[str] = Field(default_factory=list)

    model_config = {"frozen": True, "extra": "forbid"}


class PerformanceMetrics(BaseModel):
    """Performance and latency benchmark metrics for end-to-end M2 execution."""

    throughput_packages_per_sec: float = Field(..., ge=0.0)
    latency_ms_per_package: float = Field(..., ge=0.0)
    memory_mb_footprint: float = Field(..., ge=0.0)
    deterministic_pass: bool
    failure_behavior_pass: bool

    model_config = {"frozen": True, "extra": "forbid"}


def _compute_quantiles(scores: np.ndarray) -> ScoreDistributionQuantiles:
    """Calculate statistical quantiles for a 1D score array."""
    if scores.size == 0:
        return ScoreDistributionQuantiles(
            min_score=0.0,
            q25=0.0,
            median=0.0,
            q75=0.0,
            q95=0.0,
            q99=0.0,
            max_score=0.0,
            mean_score=0.0,
            std_score=0.0,
        )

    return ScoreDistributionQuantiles(
        min_score=float(np.min(scores)),
        q25=float(np.percentile(scores, 25)),
        median=float(np.median(scores)),
        q75=float(np.percentile(scores, 75)),
        q95=float(np.percentile(scores, 95)),
        q99=float(np.percentile(scores, 99)),
        max_score=float(np.max(scores)),
        mean_score=float(np.mean(scores)),
        std_score=float(np.std(scores)),
    )


def compute_unsupervised_metrics(
    scores: list[float] | np.ndarray,
    labels: list[ActivityClass | str],
    threshold: float,
) -> UnsupervisedEvaluationMetrics:
    """Compute comprehensive evaluation metrics for unsupervised anomaly detection.

    Args:
        scores: Calibrated anomaly scores [0.0, 1.0].
        labels: Ground truth activity labels.
        threshold: Operating anomaly decision threshold.

    Returns:
        UnsupervisedEvaluationMetrics object.
    """
    arr_scores = np.asarray(scores, dtype=float)
    if arr_scores.size != len(labels):
        raise ValueError("scores and labels must have equal length")

    benign_mask = np.array([
        (label == ActivityClass.BENIGN or map_cicids_label(str(label), strict=False) == ActivityClass.BENIGN)
        for label in labels
    ], dtype=bool)

    attack_mask = ~benign_mask

    benign_scores = arr_scores[benign_mask]
    attack_scores = arr_scores[attack_mask]

    # Benign False Positive Rate (FPR)
    flagged_benign = np.sum(benign_scores >= threshold) if benign_scores.size > 0 else 0
    benign_fpr = float(flagged_benign / benign_scores.size) if benign_scores.size > 0 else 0.0

    # Anomaly Detection Rate (TPR / Recall on attacks)
    flagged_attack = np.sum(attack_scores >= threshold) if attack_scores.size > 0 else 0
    anomaly_detection_rate = float(flagged_attack / attack_scores.size) if attack_scores.size > 0 else 1.0

    # ROC-AUC & PR-AUC
    roc_auc_val: Optional[float] = None
    pr_auc_val: Optional[float] = None

    if benign_scores.size > 0 and attack_scores.size > 0:
        y_binary = np.where(benign_mask, 0, 1)
        try:
            roc_auc_val = float(roc_auc_score(y_binary, arr_scores))
        except Exception:
            roc_auc_val = None

        try:
            prec_arr, rec_arr, _ = precision_recall_curve(y_binary, arr_scores)
            pr_auc_val = float(auc(rec_arr, prec_arr))
        except Exception:
            pr_auc_val = None

    benign_dist = _compute_quantiles(benign_scores)
    attack_dist = _compute_quantiles(attack_scores) if attack_scores.size > 0 else None

    # Per-activity anomaly detection rates
    per_activity_rates: dict[str, float] = {}
    activity_groups: dict[str, list[float]] = {}

    for score, label in zip(arr_scores, labels):
        ac = label if isinstance(label, ActivityClass) else map_cicids_label(str(label), strict=False)
        if isinstance(ac, ActivityClass) and ac != ActivityClass.BENIGN:
            activity_groups.setdefault(ac.value, []).append(score)

    for ac_val, group_scores in activity_groups.items():
        g_arr = np.asarray(group_scores, dtype=float)
        det = np.sum(g_arr >= threshold)
        per_activity_rates[ac_val] = float(det / g_arr.size)

    return UnsupervisedEvaluationMetrics(
        benign_fpr=benign_fpr,
        anomaly_detection_rate=anomaly_detection_rate,
        roc_auc=roc_auc_val,
        pr_auc=pr_auc_val,
        benign_distribution=benign_dist,
        attack_distribution=attack_dist,
        per_activity_detection_rates=per_activity_rates,
    )


def compute_supervised_metrics(
    y_true: list[ActivityClass | str],
    y_pred: list[ActivityClass | str],
    target_classes: list[ActivityClass] = ALL_ACTIVITY_CLASSES,
) -> SupervisedEvaluationMetrics:
    """Compute comprehensive evaluation metrics for supervised activity classification.

    Args:
        y_true: Ground truth ActivityClass labels.
        y_pred: Predicted ActivityClass values.
        target_classes: Canonical ActivityClass list.

    Returns:
        SupervisedEvaluationMetrics object.
    """
    clean_true: list[str] = []
    clean_pred: list[str] = []

    for gt, pd in zip(y_true, y_pred):
        gt_ac = gt if isinstance(gt, ActivityClass) else map_cicids_label(str(gt), strict=False)
        pd_ac = pd if isinstance(pd, ActivityClass) else map_cicids_label(str(pd), strict=False)

        if gt_ac == UNMAPPED or not isinstance(gt_ac, ActivityClass):
            continue

        clean_true.append(gt_ac.value)
        clean_pred.append(pd_ac.value if isinstance(pd_ac, ActivityClass) else "UNMAPPED")

    labels = [c.value for c in target_classes]
    if not clean_true:
        return SupervisedEvaluationMetrics(
            accuracy=0.0,
            balanced_accuracy=0.0,
            macro_f1=0.0,
            weighted_f1=0.0,
            per_class_precision={c: 0.0 for c in labels},
            per_class_recall={c: 0.0 for c in labels},
            per_class_f1={c: 0.0 for c in labels},
            confusion_matrix=[],
            class_labels=labels,
        )

    yt = np.array(clean_true)
    yp = np.array(clean_pred)
    present_labels = sorted(list(set(clean_true) | set(clean_pred)))

    acc = float(accuracy_score(yt, yp))
    bal_acc = float(balanced_accuracy_score(yt, yp))
    macro_f1 = float(f1_score(yt, yp, labels=present_labels, average="macro", zero_division=0))
    weighted_f1 = float(f1_score(yt, yp, labels=present_labels, average="weighted", zero_division=0))

    prec_arr = precision_score(yt, yp, labels=labels, average=None, zero_division=0)
    rec_arr = recall_score(yt, yp, labels=labels, average=None, zero_division=0)
    f1_arr = f1_score(yt, yp, labels=labels, average=None, zero_division=0)

    per_class_p = {label: float(val) for label, val in zip(labels, prec_arr)}
    per_class_r = {label: float(val) for label, val in zip(labels, rec_arr)}
    per_class_f = {label: float(val) for label, val in zip(labels, f1_arr)}

    cm = confusion_matrix(yt, yp, labels=labels).tolist()

    return SupervisedEvaluationMetrics(
        accuracy=acc,
        balanced_accuracy=bal_acc,
        macro_f1=macro_f1,
        weighted_f1=weighted_f1,
        per_class_precision=per_class_p,
        per_class_recall=per_class_r,
        per_class_f1=per_class_f,
        confusion_matrix=cm,
        class_labels=labels,
    )
