"""
evaluator.py
------------
M2 Phase 9 — M2 Evaluator Engine.

Evaluates unsupervised anomaly models, supervised activity models, and benchmarks end-to-end
M2 execution throughput, latency, memory footprint, and determinism.
"""

from __future__ import annotations

import logging
import psutil
import time
from typing import Any, Optional

import numpy as np

from app.contracts.analysis import ActivityClass, FeatureVector
from app.contracts.network_intelligence import NetworkIntelligencePackage
from app.engines.analysis.evaluation.metrics import (
    PerformanceMetrics,
    SupervisedEvaluationMetrics,
    UnsupervisedEvaluationMetrics,
    compute_supervised_metrics,
    compute_unsupervised_metrics,
)
from app.engines.analysis.models.anomaly.predictor import AnomalyPredictor
from app.engines.analysis.models.classification.predictor import ActivityClassifier

logger = logging.getLogger(__name__)


class M2Evaluator:
    """Production evaluator for M2 models and end-to-end pipeline benchmarking."""

    def evaluate_unsupervised(
        self,
        anomaly_predictor: AnomalyPredictor,
        vectors: list[FeatureVector],
        labels: list[ActivityClass | str],
        threshold: Optional[float] = None,
    ) -> UnsupervisedEvaluationMetrics:
        """Evaluate unsupervised anomaly model performance.

        Args:
            anomaly_predictor: Fitted AnomalyPredictor instance.
            vectors: List of input FeatureVector objects.
            labels: Ground truth activity labels.
            threshold: Optional threshold override. If None, uses artifact threshold.

        Returns:
            UnsupervisedEvaluationMetrics object.
        """
        thresh = threshold if threshold is not None else anomaly_predictor.artifact.threshold
        scores: list[float] = []

        for vector in vectors:
            pred = anomaly_predictor.predict(vector)
            scores.append(pred.result.score)

        return compute_unsupervised_metrics(scores, labels, thresh)

    def evaluate_supervised(
        self,
        activity_classifier: ActivityClassifier,
        vectors: list[FeatureVector],
        labels: list[ActivityClass | str],
    ) -> SupervisedEvaluationMetrics:
        """Evaluate supervised activity classifier performance.

        Args:
            activity_classifier: Fitted ActivityClassifier instance.
            vectors: List of input FeatureVector objects.
            labels: Ground truth activity labels.

        Returns:
            SupervisedEvaluationMetrics object.
        """
        predictions: list[ActivityClass] = []

        for vector in vectors:
            pred = activity_classifier.predict(vector)
            predictions.append(pred.result.activity_class)

        return compute_supervised_metrics(labels, predictions)

    def benchmark_pipeline(
        self,
        engine: Any,  # M2AnalysisEngine instance
        packages: list[NetworkIntelligencePackage],
    ) -> PerformanceMetrics:
        """Benchmark end-to-end M2 pipeline performance, throughput, latency, memory, and determinism.

        Args:
            engine: M2AnalysisEngine instance.
            packages: Representative NetworkIntelligencePackage test batch.

        Returns:
            PerformanceMetrics object.
        """
        if not packages:
            return PerformanceMetrics(
                throughput_packages_per_sec=0.0,
                latency_ms_per_package=0.0,
                memory_mb_footprint=0.0,
                deterministic_pass=True,
                failure_behavior_pass=True,
            )

        process = psutil.Process()
        mem_before = process.memory_info().rss / (1024 * 1024)  # MB

        start_time = time.perf_counter()
        results = []

        for pkg in packages:
            fp = engine.analyze(pkg)
            results.append(fp)

        elapsed = time.perf_counter() - start_time
        mem_after = process.memory_info().rss / (1024 * 1024)
        mem_footprint = max(0.0, mem_after - mem_before)

        throughput = len(packages) / elapsed if elapsed > 0 else 0.0
        latency_ms = (elapsed / len(packages)) * 1000.0 if len(packages) > 0 else 0.0

        # Determinism check: re-evaluate first package and check identical outputs
        deterministic_pass = True
        if packages:
            fp1 = engine.analyze(packages[0])
            fp2 = engine.analyze(packages[0])
            deterministic_pass = (fp1.findings == fp2.findings)

        # Failure behavior check: empty package does not crash and handles safely
        failure_behavior_pass = True
        try:
            empty_pkg = NetworkIntelligencePackage(
                package_id="EMPTY-PKG-001",
                acquisition_id="ACQ-EMPTY",
                flows=[],
                protocol_events=[],
                artifacts=[],
            )
            fp_empty = engine.analyze(empty_pkg)
            failure_behavior_pass = (len(fp_empty.findings) == 0)
        except Exception as e:
            logger.warning("Failure behavior check encountered exception: %s", e)
            failure_behavior_pass = False

        return PerformanceMetrics(
            throughput_packages_per_sec=round(throughput, 2),
            latency_ms_per_package=round(latency_ms, 2),
            memory_mb_footprint=round(mem_footprint, 2),
            deterministic_pass=deterministic_pass,
            failure_behavior_pass=failure_behavior_pass,
        )
