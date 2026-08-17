"""
engine.py
---------
M2 Phase 7 — Analysis Decision Engine.

Orchestrates both the unsupervised anomaly detection model (Phase 5 Isolation Forest)
and the supervised activity classification model (Phase 6 Random Forest) to produce
a combined, deterministic AnalysisDecisionResult.
"""

from __future__ import annotations

import logging
from typing import Optional

from app.contracts.analysis import ActivityClass, FeatureVector
from app.engines.analysis.decision.confidence import calculate_confidence
from app.engines.analysis.decision.result import (
    ENGINE_VERSION,
    AnalysisDecisionResult,
    DecisionState,
)
from app.engines.analysis.decision.risk import calculate_risk_score
from app.engines.analysis.models.anomaly.predictor import AnomalyPredictor
from app.engines.analysis.models.classification.predictor import ActivityClassifier

logger = logging.getLogger(__name__)

DEFAULT_ANOMALY_THRESHOLD = 0.50
DEFAULT_CONFIDENCE_THRESHOLD = 0.60


class AnalysisDecisionEngine:
    """Production decision engine orchestrating M2 anomaly detection and activity classification.

    Evaluates input feature vectors against both models and applies deterministic risk
    scoring and decision matrix logic to establish the overall DecisionState.
    """

    def __init__(
        self,
        anomaly_predictor: AnomalyPredictor,
        activity_classifier: ActivityClassifier,
        anomaly_threshold: float = DEFAULT_ANOMALY_THRESHOLD,
        confidence_threshold: float = DEFAULT_CONFIDENCE_THRESHOLD,
    ) -> None:
        self.anomaly_predictor = anomaly_predictor
        self.activity_classifier = activity_classifier
        self.anomaly_threshold = anomaly_threshold
        self.confidence_threshold = confidence_threshold

    def _determine_decision_state(
        self,
        *,
        predicted_activity: ActivityClass,
        anomaly_score: float,
        confidence: float,
        risk_score: float,
    ) -> DecisionState:
        """Evaluate decision state matrix based on combined model signals.

        Rule Logic:
          1. BENIGN predicted class:
             - If anomaly_score >= anomaly_threshold -> ANOMALOUS (unclassified anomaly).
             - Else -> BENIGN.
          2. Non-BENIGN predicted class:
             - If confidence < confidence_threshold:
               - If anomaly_score >= anomaly_threshold -> ANOMALOUS (high anomaly + low confidence -> unknown pattern).
               - Else -> SUSPICIOUS_ACTIVITY.
             - If confidence >= confidence_threshold:
               - If confidence >= 0.75 and (anomaly_score >= 0.40 or risk_score >= 0.50):
                 -> HIGH_CONFIDENCE_ACTIVITY.
               - Else -> SUSPICIOUS_ACTIVITY.
        """
        is_benign = (predicted_activity == ActivityClass.BENIGN)
        is_anomalous = (anomaly_score >= self.anomaly_threshold)
        is_high_conf = (confidence >= self.confidence_threshold)

        if is_benign:
            if is_anomalous:
                # High anomaly with benign classifier -> unknown anomalous pattern
                return DecisionState.ANOMALOUS
            return DecisionState.BENIGN

        # Non-Benign Activity
        if not is_high_conf:
            if is_anomalous:
                # High anomaly + low classification confidence -> anomalous unknown pattern
                # Do NOT claim false certainty when confidence is low
                return DecisionState.ANOMALOUS
            return DecisionState.SUSPICIOUS_ACTIVITY

        # High confidence non-benign activity
        if confidence >= 0.75 and (anomaly_score >= 0.40 or risk_score >= 0.50):
            return DecisionState.HIGH_CONFIDENCE_ACTIVITY

        return DecisionState.SUSPICIOUS_ACTIVITY

    def evaluate(self, vector: FeatureVector) -> AnalysisDecisionResult:
        """Run both models on input FeatureVector and produce combined AnalysisDecisionResult.

        Preserves raw anomaly and classification outputs separately.
        """
        # 1. Run unsupervised anomaly model
        anomaly_pred = self.anomaly_predictor.predict(vector)
        anomaly_res = anomaly_pred.result
        anomaly_score = anomaly_res.score

        # 2. Run supervised activity classifier
        cls_pred = self.activity_classifier.predict(vector)
        cls_res = cls_pred.result
        predicted_activity = cls_res.activity_class
        cls_probs = cls_res.class_probabilities

        # 3. Calculate unified confidence
        confidence = calculate_confidence(cls_res, anomaly_res)

        # 4. Calculate deterministic risk score (risk != anomaly_score)
        risk_score = calculate_risk_score(
            anomaly_score=anomaly_score,
            predicted_activity=predicted_activity,
            confidence=confidence,
            feature_vector=vector,
        )

        # 5. Determine decision state
        decision_state = self._determine_decision_state(
            predicted_activity=predicted_activity,
            anomaly_score=anomaly_score,
            confidence=confidence,
            risk_score=risk_score,
        )

        model_versions = {
            "anomaly_model": anomaly_res.model_version,
            "classification_model": cls_res.model_version,
            "decision_engine": ENGINE_VERSION,
        }

        return AnalysisDecisionResult(
            acquisition_id=vector.acquisition_id,
            raw_feature_vector=vector,
            anomaly_result=anomaly_res,
            classification_result=cls_res,
            anomaly_score=anomaly_score,
            classifier_probabilities=cls_probs,
            predicted_activity=predicted_activity,
            confidence=confidence,
            risk_score=risk_score,
            decision_state=decision_state,
            model_versions=model_versions,
        )
