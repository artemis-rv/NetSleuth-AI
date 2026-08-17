"""
test_m2_phase9_evaluation.py
----------------------------
M2 Phase 9 — Evaluation and Model Registry unit tests.

Tests unsupervised metrics, supervised metrics, threshold optimization, model registry persistence,
and evaluation report generation.
"""

import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import numpy as np

from backend.app.contracts.analysis import ActivityClass
from backend.app.contracts.feature_schema import FEATURE_SCHEMA_VERSION
from backend.app.contracts.network_intelligence import Endpoint, Flow, FlowProvenance, NetworkIntelligencePackage
from backend.app.engines.analysis.evaluation.evaluator import M2Evaluator
from backend.app.engines.analysis.evaluation.metrics import (
    compute_supervised_metrics,
    compute_unsupervised_metrics,
)
from backend.app.engines.analysis.evaluation.model_registry import ModelRegistry, RegistryArtifactEntry
from backend.app.engines.analysis.evaluation.reports import generate_m2_evaluation_report
from backend.app.engines.analysis.evaluation.threshold_optimizer import ThresholdOptimizer
from backend.app.engines.analysis.features.extractor import extract_all_features
from backend.app.engines.analysis.features.pipeline import FeatureEngineeringPipeline
from backend.app.engines.analysis.models.anomaly.isolation_forest import IsolationForestAnomalyModel
from backend.app.engines.analysis.models.anomaly.model_artifact import build_artifact as build_anomaly_artifact
from backend.app.engines.analysis.models.anomaly.predictor import AnomalyPredictor
from backend.app.engines.analysis.models.anomaly.threshold import select_threshold_from_benign_validation
from backend.app.engines.analysis.models.classification.model_artifact import (
    build_classification_artifact,
)
from backend.app.engines.analysis.models.classification.predictor import ActivityClassifier
from backend.app.engines.analysis.models.classification.random_forest import RandomForestActivityModel

ACQ_ID = "ACQ-EVAL-001"
PROV = FlowProvenance(acquisition_id=ACQ_ID, source="test", source_log="conn.log")
T0 = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def _make_flow(fid: str, orig_bytes: int, resp_bytes: int, dst_port: int = 80) -> Flow:
    return Flow(
        flow_id=fid,
        zeek_uid=f"U{fid}",
        acquisition_id=ACQ_ID,
        source=Endpoint(ip="10.0.0.1", port=12345),
        destination=Endpoint(ip="10.0.0.2", port=dst_port),
        protocol="tcp",
        timestamp=T0,
        duration=1.5,
        orig_bytes=orig_bytes,
        resp_bytes=resp_bytes,
        orig_packets=10,
        resp_packets=10,
        connection_state="SF",
        provenance=PROV,
    )


def _make_pkg(flows: list[Flow]) -> NetworkIntelligencePackage:
    return NetworkIntelligencePackage(
        package_id=f"PKG-{uuid4().hex[:8]}",
        acquisition_id=ACQ_ID,
        flows=flows,
        protocol_events=[],
        artifacts=[],
    )


def _create_registry_setup():
    pkgs = [
        _make_pkg([_make_flow("F1", 100, 200, 80)]),
        _make_pkg([_make_flow("F2", 150, 300, 80)]),
        _make_pkg([_make_flow("F3", 100000, 50000, 443)]),
        _make_pkg([_make_flow("F4", 120000, 60000, 443)]),
    ]

    pipeline = FeatureEngineeringPipeline()
    pipeline.fit(pkgs)
    transformed_dicts = [pipeline.transform(p)[0] for p in pkgs]

    feature_names = list(transformed_dicts[0].keys())
    X = np.array([[row[f] for f in feature_names] for row in transformed_dicts], dtype=float)

    anom_model = IsolationForestAnomalyModel(random_state=42)
    anom_model.fit(X[:2], feature_names)
    scores = anom_model.calibrated_scores(X[:2])
    thresh_sel = select_threshold_from_benign_validation(scores, target_fpr=0.05)
    means = {f: float(np.mean(X[:, i])) for i, f in enumerate(feature_names)}
    stds = {f: float(np.std(X[:, i])) for i, f in enumerate(feature_names)}

    anom_art = build_anomaly_artifact(
        isolation_forest=anom_model,
        transformer=pipeline.transformer,
        threshold_selection=thresh_sel,
        training_feature_means=means,
        training_feature_stds=stds,
        hyperparameters=anom_model.hyperparameters,
        random_state=42,
    )

    y = [
        ActivityClass.BENIGN,
        ActivityClass.BENIGN,
        ActivityClass.C2_MALWARE_COMMUNICATION,
        ActivityClass.C2_MALWARE_COMMUNICATION,
    ]
    cls_model = RandomForestActivityModel(random_state=42)
    cls_model.fit(X, y, feature_names)

    cls_art = build_classification_artifact(
        random_forest=cls_model,
        transformer=pipeline.transformer,
        hyperparameters=cls_model.hyperparameters,
        random_state=42,
    )

    optimizer = ThresholdOptimizer(target_fpr=0.05)
    thresh_cfg = optimizer.optimize_thresholds(scores, validation_split_name="Thursday validation")

    registry = ModelRegistry(
        anomaly_artifact=anom_art,
        classification_artifact=cls_art,
        threshold_config=thresh_cfg,
    )
    return registry


class TestUnsupervisedMetrics(unittest.TestCase):
    def test_compute_unsupervised_metrics(self):
        scores = [0.1, 0.2, 0.3, 0.8, 0.9, 0.95]
        labels = [
            ActivityClass.BENIGN,
            ActivityClass.BENIGN,
            ActivityClass.BENIGN,
            ActivityClass.SCANNING_RECONNAISSANCE,
            ActivityClass.C2_MALWARE_COMMUNICATION,
            ActivityClass.POSSIBLE_EXFILTRATION,
        ]

        metrics = compute_unsupervised_metrics(scores, labels, threshold=0.5)

        self.assertAlmostEqual(metrics.benign_fpr, 0.0)
        self.assertAlmostEqual(metrics.anomaly_detection_rate, 1.0)
        self.assertIsNotNone(metrics.roc_auc)
        self.assertAlmostEqual(metrics.roc_auc, 1.0)
        self.assertIn("SCANNING_RECONNAISSANCE", metrics.per_activity_detection_rates)


class TestSupervisedMetrics(unittest.TestCase):
    def test_compute_supervised_metrics(self):
        y_true = [ActivityClass.BENIGN, ActivityClass.SCANNING_RECONNAISSANCE]
        y_pred = [ActivityClass.BENIGN, ActivityClass.SCANNING_RECONNAISSANCE]

        metrics = compute_supervised_metrics(y_true, y_pred)

        self.assertEqual(metrics.accuracy, 1.0)
        self.assertEqual(metrics.macro_f1, 1.0)
        self.assertEqual(metrics.weighted_f1, 1.0)


class TestThresholdOptimizer(unittest.TestCase):
    def test_optimize_thresholds(self):
        optimizer = ThresholdOptimizer(target_fpr=0.05)
        benign_scores = [0.05, 0.10, 0.15, 0.20, 0.25, 0.30, 0.35, 0.40, 0.45, 0.50]

        cfg = optimizer.optimize_thresholds(benign_scores, target_fpr=0.10)
        self.assertGreaterEqual(cfg.anomaly_threshold, 0.40)
        self.assertLessEqual(cfg.observed_benign_fpr, 0.15)


class TestModelRegistryAndExports(unittest.TestCase):
    def test_registry_save_load_and_pkl_export(self):
        registry = _create_registry_setup()

        with tempfile.TemporaryDirectory() as tmpdir:
            dir_path = Path(tmpdir)
            registry.save(dir_path)

            self.assertTrue((dir_path / "model_registry.json").exists())
            self.assertTrue((dir_path / "anomaly_model.json").exists())
            self.assertTrue((dir_path / "activity_classifier.json").exists())
            self.assertTrue((dir_path / "isolation_forest.pkl").exists())
            self.assertTrue((dir_path / "activity_classifier.pkl").exists())

            restored_registry = ModelRegistry.load(dir_path)
            self.assertEqual(restored_registry.registry_id, registry.registry_id)


class TestEvaluationReport(unittest.TestCase):
    def test_generate_report(self):
        scores = [0.1, 0.8]
        labels = [ActivityClass.BENIGN, ActivityClass.C2_MALWARE_COMMUNICATION]

        u_metrics = compute_unsupervised_metrics(scores, labels, threshold=0.5)
        s_metrics = compute_supervised_metrics(labels, labels)

        optimizer = ThresholdOptimizer(target_fpr=0.05)
        thresh_cfg = optimizer.optimize_thresholds([0.1])

        report = generate_m2_evaluation_report(
            unsupervised_metrics=u_metrics,
            supervised_metrics=s_metrics,
            threshold_config=thresh_cfg,
        )

        self.assertTrue(report.validation_checks_passed)
        self.assertIn("ER-", report.report_id)


if __name__ == "__main__":
    unittest.main()
