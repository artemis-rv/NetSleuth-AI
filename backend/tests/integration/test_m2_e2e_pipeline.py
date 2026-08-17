"""
test_m2_e2e_pipeline.py
------------------------
M2 End-to-End Integration Test Suite.

Validates complete execution of M2AnalysisEngine over NetworkIntelligencePackages:
  - Benign validation
  - Attack validation
  - Deterministic inference
  - Evidence reference validity (no fabrication)
  - Contract compliance
  - Absence of MITRE dependencies
"""

import json
import unittest
from datetime import datetime, timezone
from uuid import uuid4

import numpy as np

from backend.app.contracts.analysis import (
    M2_CONTRACT_VERSION,
    ActivityClass,
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
from backend.app.engines.analysis.engine import M2AnalysisEngine
from backend.app.engines.analysis.evaluation.model_registry import ModelRegistry
from backend.app.engines.analysis.evaluation.threshold_optimizer import ThresholdOptimizer
from backend.app.engines.analysis.features.extractor import extract_all_features
from backend.app.engines.analysis.features.pipeline import FeatureEngineeringPipeline
from backend.app.engines.analysis.models.anomaly.isolation_forest import IsolationForestAnomalyModel
from backend.app.engines.analysis.models.anomaly.model_artifact import build_artifact as build_anomaly_artifact
from backend.app.engines.analysis.models.anomaly.threshold import select_threshold_from_benign_validation
from backend.app.engines.analysis.models.classification.model_artifact import (
    build_classification_artifact,
)
from backend.app.engines.analysis.models.classification.random_forest import RandomForestActivityModel

ACQ_ID = "ACQ-E2E-001"
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


def _make_pkg(flows: list[Flow], pkg_id: str = "PKG-E2E-1") -> NetworkIntelligencePackage:
    return NetworkIntelligencePackage(
        package_id=pkg_id,
        acquisition_id=ACQ_ID,
        flows=flows,
        protocol_events=[],
        artifacts=[],
    )


def _setup_engine() -> tuple[M2AnalysisEngine, NetworkIntelligencePackage, NetworkIntelligencePackage]:
    benign_pkg = _make_pkg([_make_flow("F1", 100, 200, 80)], pkg_id="PKG-BENIGN")
    attack_pkg = _make_pkg([_make_flow("F3", 100000, 50000, 443)], pkg_id="PKG-ATTACK")

    pkgs = [
        benign_pkg,
        _make_pkg([_make_flow("F2", 150, 300, 80)], pkg_id="PKG-BENIGN-2"),
        attack_pkg,
        _make_pkg([_make_flow("F4", 120000, 60000, 443)], pkg_id="PKG-ATTACK-2"),
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
    thresh_cfg = optimizer.optimize_thresholds(scores)

    registry = ModelRegistry(
        anomaly_artifact=anom_art,
        classification_artifact=cls_art,
        threshold_config=thresh_cfg,
    )

    engine = M2AnalysisEngine.from_registry(registry)
    return engine, benign_pkg, attack_pkg


class TestM2E2EPipeline(unittest.TestCase):
    def setUp(self):
        self.engine, self.benign_pkg, self.attack_pkg = _setup_engine()

    def test_benign_pipeline_execution(self):
        """Benign package analysis produces valid FindingsPackage."""
        fp = self.engine.analyze(self.benign_pkg)
        self.assertIsInstance(fp, FindingsPackage)
        self.assertEqual(fp.acquisition_id, ACQ_ID)
        self.assertEqual(fp.source_package_id, self.benign_pkg.package_id)
        self.assertEqual(fp.contract_version, M2_CONTRACT_VERSION)

    def test_attack_pipeline_execution(self):
        """Attack package analysis produces valid evidence-backed FindingsPackage."""
        fp = self.engine.analyze(self.attack_pkg)
        self.assertIsInstance(fp, FindingsPackage)
        self.assertEqual(fp.acquisition_id, ACQ_ID)
        self.assertGreater(len(fp.findings), 0)

        finding = fp.findings[0]
        self.assertIsInstance(finding, Finding)
        self.assertIn(finding.activity_class, list(ActivityClass))
        self.assertGreater(len(finding.evidence_references), 0)

    def test_deterministic_inference(self):
        """Running analyze() twice on same package produces 100% identical FindingsPackage findings."""
        fp1 = self.engine.analyze(self.attack_pkg)
        fp2 = self.engine.analyze(self.attack_pkg)

        self.assertEqual(len(fp1.findings), len(fp2.findings))
        for f1, f2 in zip(fp1.findings, fp2.findings):
            self.assertEqual(f1.activity_class, f2.activity_class)
            self.assertAlmostEqual(f1.anomaly_score, f2.anomaly_score, places=6)
            self.assertAlmostEqual(f1.risk_score, f2.risk_score, places=6)
            self.assertAlmostEqual(f1.classification_confidence, f2.classification_confidence, places=6)

    def test_evidence_reference_validity(self):
        """All flow IDs referenced in EvidenceReference must exist in the source package."""
        fp = self.engine.analyze(self.attack_pkg)
        valid_flow_ids = {f.flow_id for f in self.attack_pkg.flows}

        for finding in fp.findings:
            for ref in finding.evidence_references:
                for fid in ref.flow_ids:
                    self.assertIn(fid, valid_flow_ids)

    def test_no_mitre_dependency(self):
        """Assert FindingsPackage JSON output contains NO MITRE technique/tactic IDs."""
        fp = self.engine.analyze(self.attack_pkg)
        json_str = fp.model_dump_json().lower()

        self.assertNotIn("mitre", json_str)
        self.assertNotIn("t1046", json_str)
        self.assertNotIn("t1071", json_str)
        self.assertNotIn("tactic", json_str)
        self.assertNotIn("attack_chain", json_str)


if __name__ == "__main__":
    unittest.main()
