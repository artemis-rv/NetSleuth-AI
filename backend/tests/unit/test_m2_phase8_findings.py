"""
test_m2_phase8_findings.py
--------------------------
M2 Phase 8 — Evidence Attribution and FindingsPackage Generation unit tests.

Tests finding generation, evidence reference validity, prevention of fabricated evidence,
acquisition integrity, model metadata, empty finding case, multiple findings, and deterministic serialization.
"""

import json
import unittest
from datetime import datetime, timezone
from uuid import uuid4

import numpy as np

from backend.app.contracts.analysis import (
    M2_CONTRACT_VERSION,
    ActivityClass,
    AnomalyResult,
    ClassificationResult,
    EvidenceReference,
    Finding,
    FindingsPackage,
)
from backend.app.contracts.feature_schema import FEATURE_SCHEMA_VERSION
from backend.app.contracts.network_intelligence import (
    Endpoint,
    Flow,
    FlowProvenance,
    NetworkIntelligencePackage,
)
from backend.app.engines.analysis.decision.engine import AnalysisDecisionEngine
from backend.app.engines.analysis.decision.result import AnalysisDecisionResult, DecisionState
from backend.app.engines.analysis.features.extractor import extract_all_features
from backend.app.engines.analysis.features.pipeline import FeatureEngineeringPipeline
from backend.app.engines.analysis.findings.attribution import FeatureAttributor
from backend.app.engines.analysis.findings.builder import FindingBuilder
from backend.app.engines.analysis.findings.errors import FabricatedEvidenceError, MissingSourcePackageError
from backend.app.engines.analysis.findings.generator import FindingsGenerator
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

ACQ_ID = "ACQ-FINDINGS-001"
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


def _create_setup():
    """Create trained decision engine and test package."""
    pkg = _make_pkg([
        _make_flow("F1", 100, 200, 80),
        _make_flow("F2", 150, 300, 80),
        _make_flow("F3", 100000, 50000, 443),
    ])

    pkgs = [
        _make_pkg([_make_flow("F1", 100, 200, 80)]),
        _make_pkg([_make_flow("F2", 150, 300, 80)]),
        _make_pkg([_make_flow("F3", 100000, 50000, 443)]),
        _make_pkg([_make_flow("F4", 120000, 60000, 443)]),
    ]

    pipeline = FeatureEngineeringPipeline()
    feature_vector = extract_all_features(pkg)
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
    anom_pred = AnomalyPredictor.from_artifact(anom_art)

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
    cls_pred = ActivityClassifier.from_artifact(cls_art)

    engine = AnalysisDecisionEngine(anomaly_predictor=anom_pred, activity_classifier=cls_pred)
    return engine, pkg, feature_vector


class TestFindingsGeneration(unittest.TestCase):
    def setUp(self):
        self.engine, self.pkg, self.vector = _create_setup()
        self.generator = FindingsGenerator()

    def test_finding_generation(self):
        decision_res = self.engine.evaluate(self.vector)
        findings_pkg = self.generator.generate(self.pkg, self.vector, decision_res)

        self.assertIsInstance(findings_pkg, FindingsPackage)
        self.assertEqual(findings_pkg.acquisition_id, self.pkg.acquisition_id)
        self.assertEqual(findings_pkg.source_package_id, self.pkg.package_id)
        self.assertEqual(findings_pkg.contract_version, M2_CONTRACT_VERSION)

        if findings_pkg.findings:
            f = findings_pkg.findings[0]
            self.assertIsInstance(f, Finding)
            self.assertEqual(f.acquisition_id, self.pkg.acquisition_id)
            self.assertIsNotNone(f.evidence_references)
            self.assertGreater(len(f.evidence_references), 0)

    def test_evidence_references_valid(self):
        """Every flow_id in EvidenceReference must exist in source package."""
        decision_res = self.engine.evaluate(self.vector)
        findings_pkg = self.generator.generate(self.pkg, self.vector, decision_res)

        valid_flow_ids = {flow.flow_id for flow in self.pkg.flows}

        for finding in findings_pkg.findings:
            for ref in finding.evidence_references:
                for fid in ref.flow_ids:
                    self.assertIn(fid, valid_flow_ids)

    def test_no_fabricated_evidence(self):
        """Attributor must raise FabricatedEvidenceError if invalid object ID is introduced."""
        attributor = FeatureAttributor(strict_validation=True)
        bad_ref = EvidenceReference(
            flow_ids=["FABRICATED_FLOW_9999"],
            event_ids=[],
            artifact_ids=[],
            rationale="Test rationale",
        )
        with self.assertRaises(FabricatedEvidenceError):
            attributor.validate_evidence_references(self.pkg, [bad_ref])

    def test_acquisition_integrity(self):
        decision_res = self.engine.evaluate(self.vector)
        findings_pkg = self.generator.generate(self.pkg, self.vector, decision_res)

        self.assertEqual(findings_pkg.acquisition_id, ACQ_ID)
        for f in findings_pkg.findings:
            self.assertEqual(f.acquisition_id, ACQ_ID)

    def test_model_metadata(self):
        decision_res = self.engine.evaluate(self.vector)
        findings_pkg = self.generator.generate(self.pkg, self.vector, decision_res)

        self.assertIsNotNone(findings_pkg.feature_schema_version)
        self.assertIsNotNone(findings_pkg.anomaly_model_version)
        self.assertIsNotNone(findings_pkg.classifier_model_version)
        self.assertEqual(findings_pkg.feature_schema_version, FEATURE_SCHEMA_VERSION)

    def test_empty_finding_case(self):
        """Benign decision state with no anomaly must yield empty findings list."""
        benign_pkg = _make_pkg([_make_flow("F10", 100, 200, 80)])
        benign_vec = extract_all_features(benign_pkg)
        benign_res = self.engine.evaluate(benign_vec)

        benign_anom_res = AnomalyResult(
            anomaly_detected=False,
            score=0.1,
            threshold=0.5,
            model_id="AM-TEST",
            model_version="1.0",
        )

        benign_res_forced = AnalysisDecisionResult(
            acquisition_id=benign_pkg.acquisition_id,
            raw_feature_vector=benign_vec,
            anomaly_result=benign_anom_res,
            classification_result=benign_res.classification_result,
            anomaly_score=0.1,
            classifier_probabilities={ac.value: 0.0 for ac in ALL_ACTIVITY_CLASSES},
            predicted_activity=ActivityClass.BENIGN,
            confidence=0.95,
            risk_score=0.05,
            decision_state=DecisionState.BENIGN,
            model_versions=benign_res.model_versions,
        )

        fp = self.generator.generate(benign_pkg, benign_vec, benign_res_forced)
        self.assertEqual(len(fp.findings), 0)

    def test_deterministic_serialization(self):
        decision_res = self.engine.evaluate(self.vector)
        fp = self.generator.generate(self.pkg, self.vector, decision_res)

        json_str = fp.model_dump_json(indent=2)
        fp_restored = FindingsPackage.model_validate_json(json_str)

        self.assertEqual(fp.package_id, fp_restored.package_id)
        self.assertEqual(fp.acquisition_id, fp_restored.acquisition_id)
        self.assertEqual(len(fp.findings), len(fp_restored.findings))


if __name__ == "__main__":
    unittest.main()
