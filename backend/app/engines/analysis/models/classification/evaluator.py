"""
evaluator.py
------------
M2 Phase 6 — Supervised Activity Classifier Evaluation.

Calculates standard classification performance metrics on validation/test sets:
  - accuracy
  - macro F1
  - weighted F1
  - per-class precision
  - per-class recall
  - confusion matrix
  - balanced accuracy
"""

from __future__ import annotations

from typing import Any, Optional
import numpy as np
from pydantic import BaseModel, Field
from sklearn.metrics import (
    accuracy_score,
    balanced_accuracy_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)

from backend.app.contracts.analysis import ActivityClass
from backend.app.engines.analysis.dataset.labels import UNMAPPED
from backend.app.engines.analysis.models.classification.label_map import (
    ALL_ACTIVITY_CLASSES,
    map_cicids_label,
)


class ClassificationEvaluationReport(BaseModel):
    """Structured performance report for activity classification evaluation."""

    accuracy: float = Field(..., ge=0.0, le=1.0)
    macro_f1: float = Field(..., ge=0.0, le=1.0)
    weighted_f1: float = Field(..., ge=0.0, le=1.0)
    balanced_accuracy: float = Field(..., ge=0.0, le=1.0)
    per_class_precision: dict[str, float] = Field(default_factory=dict)
    per_class_recall: dict[str, float] = Field(default_factory=dict)
    per_class_f1: dict[str, float] = Field(default_factory=dict)
    confusion_matrix: list[list[int]] = Field(default_factory=list)
    class_labels: list[str] = Field(default_factory=list)
    total_samples: int = Field(..., ge=0)
    excluded_unmapped_samples: int = Field(0, ge=0)

    model_config = {"frozen": True, "extra": "forbid"}

    def to_dict(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def evaluate_classifier(
    y_true: list[ActivityClass | str],
    y_pred: list[ActivityClass | str],
    target_classes: Optional[list[ActivityClass]] = None,
) -> ClassificationEvaluationReport:
    """Evaluate predictions against ground-truth labels.

    Args:
        y_true: Ground truth labels (ActivityClass or raw CICIDS string).
        y_pred: Predicted ActivityClass values.
        target_classes: List of canonical ActivityClasses to include in report. Default ALL_ACTIVITY_CLASSES.

    Returns:
        ClassificationEvaluationReport object.
    """
    clean_true: list[str] = []
    clean_pred: list[str] = []
    excluded_count = 0

    for gt, pd in zip(y_true, y_pred):
        gt_ac = gt if isinstance(gt, ActivityClass) else map_cicids_label(str(gt), strict=False)
        pd_ac = pd if isinstance(pd, ActivityClass) else map_cicids_label(str(pd), strict=False)

        if gt_ac == UNMAPPED or not isinstance(gt_ac, ActivityClass):
            excluded_count += 1
            continue

        if pd_ac == UNMAPPED or not isinstance(pd_ac, ActivityClass):
            clean_true.append(gt_ac.value)
            clean_pred.append("UNMAPPED")
            continue

        clean_true.append(gt_ac.value)
        clean_pred.append(pd_ac.value)

    all_taxonomy_labels = [c.value for c in ALL_ACTIVITY_CLASSES]
    labels = [c.value for c in target_classes] if target_classes else all_taxonomy_labels

    if not clean_true:
        return ClassificationEvaluationReport(
            accuracy=0.0,
            macro_f1=0.0,
            weighted_f1=0.0,
            balanced_accuracy=0.0,
            per_class_precision={c: 0.0 for c in labels},
            per_class_recall={c: 0.0 for c in labels},
            per_class_f1={c: 0.0 for c in labels},
            confusion_matrix=[],
            class_labels=labels,
            total_samples=0,
            excluded_unmapped_samples=excluded_count,
        )

    yt = np.array(clean_true)
    yp = np.array(clean_pred)

    # Present classes in true/pred
    present_labels = sorted(list(set(clean_true) | set(clean_pred)))

    acc = float(accuracy_score(yt, yp))
    macro = float(f1_score(yt, yp, labels=present_labels, average="macro", zero_division=0))
    weighted = float(f1_score(yt, yp, labels=present_labels, average="weighted", zero_division=0))
    bal_acc = float(balanced_accuracy_score(yt, yp))

    prec_arr = precision_score(yt, yp, labels=labels, average=None, zero_division=0)
    rec_arr = recall_score(yt, yp, labels=labels, average=None, zero_division=0)
    f1_arr = f1_score(yt, yp, labels=labels, average=None, zero_division=0)

    per_class_p = {label: float(val) for label, val in zip(labels, prec_arr)}
    per_class_r = {label: float(val) for label, val in zip(labels, rec_arr)}
    per_class_f = {label: float(val) for label, val in zip(labels, f1_arr)}

    cm = confusion_matrix(yt, yp, labels=labels)
    cm_list = cm.tolist()

    return ClassificationEvaluationReport(
        accuracy=acc,
        macro_f1=macro,
        weighted_f1=weighted,
        balanced_accuracy=bal_acc,
        per_class_precision=per_class_p,
        per_class_recall=per_class_r,
        per_class_f1=per_class_f,
        confusion_matrix=cm_list,
        class_labels=labels,
        total_samples=len(clean_true),
        excluded_unmapped_samples=excluded_count,
    )
