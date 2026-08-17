"""
test_m2_phase7_decision.py
--------------------------
M2 Phase 7 — Analysis Decision Engine unit tests.

Tests benign state, anomalous unknown state, high-confidence classification,
low-confidence classification, conflicting model outputs, and deterministic risk calculation.
"""

import unittest
from datetime import datetime, timezone
from uuid import uuid4

import numpy as np

from backend.app.contracts.analysis import (
    ActivityClass,
    AnomalyResult,
    ClassificationResult,
    FeatureValue,
    FeatureVector,
)
from backend.app.contracts.feature_schema import FEATURE_SCHEMA_VERSION
from backend.app.contracts.network_intelligence import (
    Endpoint,
    Flow,
    FlowProvenance,
    NetworkIntelligencePackage,
)
from backend.app.engines.analysis.decision.confidence import calculate_confidence
from backend.app.engines.analysis.decision.engine import AnalysisDecisionEngine
from backend.app.engines.analysis.decision.result import DecisionState
from backend.app.engines.analysis.decision.risk import calculate_risk_score
from backend.app.engines.analysis.features.extractor import extract_all_features
from backend.app.engines.analysis.features.pipeline import FeatureEngineeringPipeline
from backend.app.engines.analysis.models.anomaly.isolation_forest import IsolationForestAnomalyModel
from backend.app.engines.analysis.models.anomaly.model_artifact import build_artifact as build_anomaly_artifact
from backend.app.engines.analysis.models.anomaly.predictor import AnomalyPredictor
from backend.app.engines.analysis.models.anomaly.threshold import select_threshold_from_benign_validation
from backend.app.engines.analysis.models.classification.label_map import ALL_ACTIVITY_CLASSES
from backend.app.engines.analysis.models.classification.model_artifact import (
    build_classification_artifact,
)
from backend.app.engines.analysis.models.classification.predictor import ActivityClassifier
from backend.app.engines.analysis.models.classification.random_forest import RandomForestActivityModel

ACQ_ID = "ACQ-DECISION-001"
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


def _create_trained_decision_engine():
    """Construct a fully fitted AnomalyPredictor, ActivityClassifier, and AnalysisDecisionEngine."""
    pkgs = [
        _make_pkg([_make_flow("F1", 100, 200, 80)]),
        _make_pkg([_make_flow("F2", 150, 300, 80)]),
        _make_pkg([_make_flow("F3", 5000, 100, 22)]),
        _make_pkg([_make_flow("F4", 6000, 120, 22)]),
        _make_pkg([_make_flow("F5", 100000, 50000, 443)]),
        _make_pkg([_make_flow("F6", 120000, 60000, 443)]),
        _make_pkg([_make_flow("F7", 200, 800, 8080)]),
        _make_pkg([_make_flow("F8", 250, 900, 8080)]),
    ]

    pipeline = FeatureEngineeringPipeline()
    raw_vectors = [extract_all_features(p) for p in pkgs]
    pipeline.fit(pkgs)
    transformed_dicts = [pipeline.transform(p)[0] for p in pkgs]

    feature_names = list(transformed_dicts[0].keys())
    X = np.array([[row[f] for f in feature_names] for row in transformed_dicts], dtype=float)

    # 1. Fit Anomaly Model
    anom_model = IsolationForestAnomalyModel(random_state=42)
    anom_model.fit(X[:2], feature_names)  # fit benign
    calibrated_scores = anom_model.calibrated_scores(X[:2])
    thresh_sel = select_threshold_from_benign_validation(calibrated_scores, target_fpr=0.05)

    means = {f: float(np.mean(X[:, i])) for i, f in enumerate(feature_names)}
    stds = {f: float(np.std(X[:, i])) for i, f in enumerate(feature_names)}

    anom_artifact = build_anomaly_artifact(
        isolation_forest=anom_model,
        transformer=pipeline.transformer,
        threshold_selection=thresh_sel,
        training_feature_means=means,
        training_feature_stds=stds,
        hyperparameters=anom_model.hyperparameters,
        random_state=42,
    )
    anom_predictor = AnomalyPredictor.from_artifact(anom_artifact)

    # 2. Fit Activity Classifier
    y = [
        ActivityClass.BENIGN,
        ActivityClass.BENIGN,
        ActivityClass.SCANNING_RECONNAISSANCE,
        ActivityClass.SCANNING_RECONNAISSANCE,
        ActivityClass.C2_MALWARE_COMMUNICATION,
        ActivityClass.C2_MALWARE_COMMUNICATION,
        ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
        ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
    ]
    cls_model = RandomForestActivityModel(random_state=42)
    cls_model.fit(X, y, feature_names)

    cls_artifact = build_classification_artifact(
        random_forest=cls_model,
        transformer=pipeline.transformer,
        hyperparameters=cls_model.hyperparameters,
        random_state=42,
    )
    cls_predictor = ActivityClassifier.from_artifact(cls_artifact)

    engine = AnalysisDecisionEngine(
        anomaly_predictor=anom_predictor,
        activity_classifier=cls_predictor,
    )

    return engine, raw_vectors


class TestDeterministicRiskCalculation(unittest.TestCase):
    def test_risk_not_equal_to_anomaly_score(self):
        """Risk calculation MUST NOT equal simple anomaly score."""
        r1 = calculate_risk_score(
            anomaly_score=0.8,
            predicted_activity=ActivityClass.BENIGN,
            confidence=0.9,
        )
        self.assertNotEqual(r1, 0.8)

        r2 = calculate_risk_score(
            anomaly_score=0.8,
            predicted_activity=ActivityClass.C2_MALWARE_COMMUNICATION,
            confidence=0.9,
        )
        self.assertNotEqual(r2, 0.8)
        # Malicious class severity must yield higher risk than benign class for same anomaly score
        self.assertGreater(r2, r1)

    def test_risk_deterministic(self):
        """Risk calculation is 100% deterministic."""
        r1 = calculate_risk_score(
            anomaly_score=0.7,
            predicted_activity=ActivityClass.POSSIBLE_EXFILTRATION,
            confidence=0.85,
        )
        r2 = calculate_risk_score(
            anomaly_score=0.7,
            predicted_activity=ActivityClass.POSSIBLE_EXFILTRATION,
            confidence=0.85,
        )
        self.assertEqual(r1, r2)
        self.assertGreaterEqual(r1, 0.0)
        self.assertLessEqual(r1, 1.0)


class TestDecisionEngineStates(unittest.TestCase):
    def setUp(self):
        self.engine, self.raw_vectors = _create_trained_decision_engine()

    def test_benign_decision(self):
        """Benign flow with low anomaly yields BENIGN decision state."""
        res = self.engine.evaluate(self.raw_vectors[0])

        self.assertIsInstance(res.decision_state, DecisionState)
        self.assertEqual(res.predicted_activity, ActivityClass.BENIGN)
        self.assertEqual(res.decision_state, DecisionState.BENIGN)
        self.assertIsNotNone(res.anomaly_result)
        self.assertIsNotNone(res.classification_result)

    def test_high_confidence_classification(self):
        """High volume C2 traffic yields HIGH_CONFIDENCE_ACTIVITY decision state."""
        res = self.engine.evaluate(self.raw_vectors[4])  # C2 flow

        self.assertEqual(res.predicted_activity, ActivityClass.C2_MALWARE_COMMUNICATION)
        self.assertIn(
            res.decision_state,
            [DecisionState.HIGH_CONFIDENCE_ACTIVITY, DecisionState.SUSPICIOUS_ACTIVITY],
        )

    def test_anomalous_unknown_state_logic(self):
        """High anomaly score combined with low classification confidence yields ANOMALOUS state."""
        state = self.engine._determine_decision_state(
            predicted_activity=ActivityClass.C2_MALWARE_COMMUNICATION,
            anomaly_score=0.85,
            confidence=0.30,  # low classification confidence
            risk_score=0.60,
        )
        # Must yield ANOMALOUS (unknown behavioral pattern), NOT claim certainty for C2
        self.assertEqual(state, DecisionState.ANOMALOUS)

    def test_low_confidence_non_anomalous_logic(self):
        """Low classification confidence without anomaly yields SUSPICIOUS_ACTIVITY without claiming certainty."""
        state = self.engine._determine_decision_state(
            predicted_activity=ActivityClass.SUSPICIOUS_WEB_ACTIVITY,
            anomaly_score=0.20,
            confidence=0.35,  # low classification confidence
            risk_score=0.30,
        )
        self.assertEqual(state, DecisionState.SUSPICIOUS_ACTIVITY)

    def test_conflicting_model_outputs(self):
        """Handling conflicting signals (high anomaly but benign classification vs low anomaly but non-benign)."""
        # High anomaly + Benign classifier -> ANOMALOUS
        state1 = self.engine._determine_decision_state(
            predicted_activity=ActivityClass.BENIGN,
            anomaly_score=0.80,
            confidence=0.90,
            risk_score=0.40,
        )
        self.assertEqual(state1, DecisionState.ANOMALOUS)

        # Low anomaly + High confidence non-benign -> SUSPICIOUS_ACTIVITY / HIGH_CONFIDENCE_ACTIVITY
        state2 = self.engine._determine_decision_state(
            predicted_activity=ActivityClass.SCANNING_RECONNAISSANCE,
            anomaly_score=0.10,
            confidence=0.95,
            risk_score=0.55,
        )
        self.assertEqual(state2, DecisionState.HIGH_CONFIDENCE_ACTIVITY)


if __name__ == "__main__":
    unittest.main()
