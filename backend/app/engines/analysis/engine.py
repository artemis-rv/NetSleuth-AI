"""
engine.py
---------
M2 Production Entry Point — M2AnalysisEngine.

Orchestrates the entire M2 pipeline end-to-end:
NetworkIntelligencePackage -> FeatureVector -> AnomalyPredictor -> ActivityClassifier -> AnalysisDecisionEngine -> FindingsPackage.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from app.contracts.analysis import FindingsPackage
from app.contracts.network_intelligence import NetworkIntelligencePackage
from app.engines.analysis.decision.engine import AnalysisDecisionEngine
from app.engines.analysis.evaluation.model_registry import ModelRegistry
from app.engines.analysis.features.extractor import extract_all_features
from app.engines.analysis.features.pipeline import FeatureEngineeringPipeline
from app.engines.analysis.findings.generator import FindingsGenerator
from app.engines.analysis.models.anomaly.predictor import AnomalyPredictor
from app.engines.analysis.models.classification.predictor import ActivityClassifier

logger = logging.getLogger(__name__)


class M2AnalysisEngine:
    """Main production analysis engine for M2.

    Transforms raw NetworkIntelligencePackages into evidence-backed FindingsPackages
    consumable by M3.
    """

    def __init__(
        self,
        anomaly_predictor: AnomalyPredictor,
        activity_classifier: ActivityClassifier,
        decision_engine: Optional[AnalysisDecisionEngine] = None,
        findings_generator: Optional[FindingsGenerator] = None,
        pipeline: Optional[FeatureEngineeringPipeline] = None,
    ) -> None:
        self.anomaly_predictor = anomaly_predictor
        self.activity_classifier = activity_classifier
        self.decision_engine = decision_engine or AnalysisDecisionEngine(
            anomaly_predictor=anomaly_predictor,
            activity_classifier=activity_classifier,
            anomaly_threshold=anomaly_predictor.artifact.threshold,
        )
        self.findings_generator = findings_generator or FindingsGenerator()
        self.pipeline = pipeline or FeatureEngineeringPipeline()

    @classmethod
    def from_registry(cls, registry: ModelRegistry) -> "M2AnalysisEngine":
        """Instantiate M2AnalysisEngine from a registered ModelRegistry."""
        anom_pred = AnomalyPredictor.from_artifact(registry.anomaly_artifact)
        cls_pred = ActivityClassifier.from_artifact(registry.classification_artifact)

        decision_engine = AnalysisDecisionEngine(
            anomaly_predictor=anom_pred,
            activity_classifier=cls_pred,
            anomaly_threshold=registry.threshold_config.anomaly_threshold,
            confidence_threshold=registry.threshold_config.confidence_threshold,
        )

        return cls(
            anomaly_predictor=anom_pred,
            activity_classifier=cls_pred,
            decision_engine=decision_engine,
        )

    @classmethod
    def from_directory(cls, directory: Path | str) -> "M2AnalysisEngine":
        """Instantiate M2AnalysisEngine from a directory containing model_registry.json."""
        registry = ModelRegistry.load(directory)
        return cls.from_registry(registry)

    def analyze(self, package: NetworkIntelligencePackage) -> FindingsPackage:
        """Run full end-to-end M2 analysis over a NetworkIntelligencePackage.

        Args:
            package: Source NetworkIntelligencePackage.

        Returns:
            Evidence-backed FindingsPackage object.
        """
        # 1. Extract raw FeatureVector
        feature_vector = extract_all_features(package)

        # 2. Run decision engine (runs anomaly + classification + risk + decision)
        decision_result = self.decision_engine.evaluate(feature_vector)

        # 3. Generate findings package with evidence attribution
        findings_package = self.findings_generator.generate(package, feature_vector, decision_result)

        return findings_package
