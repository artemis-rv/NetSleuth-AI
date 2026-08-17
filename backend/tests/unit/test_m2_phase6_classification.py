"""
test_m2_phase6_classification.py
--------------------------------
M2 Phase 6 — Supervised Activity Classification unit tests.

Tests model training, deterministic training, serialization, inference, confidence calculation,
unknown feature rejection, schema mismatch, class mapping validation, class imbalance handling,
zero-sample class handling, and leakage validations.
"""

import json
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import numpy as np

from backend.app.contracts.analysis import ActivityClass, FeatureValue, FeatureVector
from backend.app.contracts.feature_schema import FEATURE_SCHEMA_VERSION, FeatureName
from backend.app.contracts.network_intelligence import (
    Endpoint,
    Flow,
    FlowProvenance,
    NetworkIntelligencePackage,
)
from backend.app.engines.analysis.dataset.labels import UNMAPPED
from backend.app.engines.analysis.features.extractor import extract_all_features
from backend.app.engines.analysis.features.pipeline import FeatureEngineeringPipeline
from backend.app.engines.analysis.features.transformer import FeatureTransformer
from backend.app.engines.analysis.models.classification.errors import (
    LabelMappingError,
    MissingFeatureError,
    ModelNotFittedError,
    SchemaVersionMismatchError,
)
from backend.app.engines.analysis.models.classification.evaluator import evaluate_classifier
from backend.app.engines.analysis.models.classification.label_map import (
    ALL_ACTIVITY_CLASSES,
    CICIDS_LABEL_MAP,
    LABEL_MAPPING_VERSION,
    map_cicids_label,
    validate_activity_class,
)
from backend.app.engines.analysis.models.classification.leakage_validator import (
    validate_identifier_leakage,
    validate_label_leakage,
    validate_temporal_split,
)
from backend.app.engines.analysis.models.classification.model_artifact import (
    ClassificationModelArtifact,
    build_classification_artifact,
)
from backend.app.engines.analysis.models.classification.predictor import ActivityClassifier
from backend.app.engines.analysis.models.classification.random_forest import RandomForestActivityModel

ACQ_ID = "ACQ-TEST-001"
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


def _create_sample_vectors_and_labels():
    """Create synthetic training dataset vectors and ground-truth activity labels."""
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

    # Feature names
    feature_names = list(transformed_dicts[0].keys())

    # Matrix X
    X = np.array([[row[f] for f in feature_names] for row in transformed_dicts], dtype=float)

    # Labels covering BENIGN, SCANNING_RECONNAISSANCE, C2_MALWARE_COMMUNICATION, SUSPICIOUS_WEB_ACTIVITY
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

    return pipeline, raw_vectors, X, y, feature_names


class TestClassMappingValidation(unittest.TestCase):
    def test_explicit_cicids_mapping(self):
        """Verify explicit CICIDS source label to M2 ActivityClass mapping."""
        self.assertEqual(map_cicids_label("BENIGN"), ActivityClass.BENIGN)
        self.assertEqual(map_cicids_label("FTP-Patator"), ActivityClass.SCANNING_RECONNAISSANCE)
        self.assertEqual(map_cicids_label("SSH-Patator"), ActivityClass.SCANNING_RECONNAISSANCE)
        self.assertEqual(map_cicids_label("Portscan"), ActivityClass.SCANNING_RECONNAISSANCE)
        self.assertEqual(map_cicids_label("DoS GoldenEye"), ActivityClass.C2_MALWARE_COMMUNICATION)
        self.assertEqual(map_cicids_label("DDoS"), ActivityClass.C2_MALWARE_COMMUNICATION)
        self.assertEqual(map_cicids_label("Botnet"), ActivityClass.C2_MALWARE_COMMUNICATION)
        self.assertEqual(map_cicids_label("Infiltration"), ActivityClass.POSSIBLE_EXFILTRATION)
        self.assertEqual(map_cicids_label("Web Attack - XSS"), ActivityClass.SUSPICIOUS_WEB_ACTIVITY)

    def test_no_mitre_in_mapping(self):
        """Verify MITRE IDs or tactics are absent from M2 label map."""
        for raw_label, target in CICIDS_LABEL_MAP.items():
            if isinstance(target, ActivityClass):
                val = target.value.lower()
                self.assertNotIn("t1", val)
                self.assertNotIn("mitre", val)
                self.assertNotIn("tactic", val)

    def test_uncertain_and_unmapped_labels(self):
        """Uncertain/unmapped labels must map to UNMAPPED and raise in strict mode."""
        self.assertEqual(map_cicids_label("Heartbleed"), UNMAPPED)
        self.assertEqual(map_cicids_label("Unknown Attack XYZ"), UNMAPPED)

        with self.assertRaises(LabelMappingError):
            map_cicids_label("Heartbleed", strict=True)

        with self.assertRaises(LabelMappingError):
            map_cicids_label("Unknown Attack XYZ", strict=True)

    def test_validate_activity_class(self):
        self.assertEqual(validate_activity_class(ActivityClass.BENIGN), ActivityClass.BENIGN)
        self.assertEqual(validate_activity_class("BENIGN"), ActivityClass.BENIGN)
        with self.assertRaises(LabelMappingError):
            validate_activity_class("INVALID_CLASS_NAME")


class TestModelTraining(unittest.TestCase):
    def setUp(self):
        self.pipeline, self.raw_vectors, self.X, self.y, self.feature_names = (
            _create_sample_vectors_and_labels()
        )

    def test_fit_and_predict(self):
        model = RandomForestActivityModel(random_state=42)
        self.assertFalse(model.is_fitted)

        model.fit(self.X, self.y, self.feature_names)
        self.assertTrue(model.is_fitted)

        predictions = model.predict(self.X)
        self.assertEqual(len(predictions), len(self.y))

        for top_class, conf, prob_dict in predictions:
            self.assertIsInstance(top_class, ActivityClass)
            self.assertGreaterEqual(conf, 0.0)
            self.assertLessEqual(conf, 1.0)
            self.assertEqual(set(prob_dict.keys()), {ac.value for ac in ALL_ACTIVITY_CLASSES})
            self.assertAlmostEqual(sum(prob_dict.values()), 1.0, places=5)

    def test_unfitted_model_raises(self):
        model = RandomForestActivityModel()
        with self.assertRaises(ModelNotFittedError):
            model.predict(self.X)
        with self.assertRaises(ModelNotFittedError):
            model.to_dict()


class TestDeterministicTraining(unittest.TestCase):
    def setUp(self):
        _, _, self.X, self.y, self.feature_names = _create_sample_vectors_and_labels()

    def test_deterministic_outputs(self):
        m1 = RandomForestActivityModel(random_state=42)
        m1.fit(self.X, self.y, self.feature_names)

        m2 = RandomForestActivityModel(random_state=42)
        m2.fit(self.X, self.y, self.feature_names)

        p1 = m1.predict_proba_dict(self.X)
        p2 = m2.predict_proba_dict(self.X)

        self.assertEqual(len(p1), len(p2))
        for row1, row2 in zip(p1, p2):
            for k in row1:
                self.assertAlmostEqual(row1[k], row2[k], places=7)


class TestInsufficientClassHandling(unittest.TestCase):
    def setUp(self):
        _, _, self.X, self.y, self.feature_names = _create_sample_vectors_and_labels()

    def test_missing_class_preservation(self):
        """Classes absent from training set (e.g. DNS_ANOMALY_TUNNELING) must have 0.0 probability."""
        model = RandomForestActivityModel(random_state=42)
        model.fit(self.X, self.y, self.feature_names)

        self.assertIn(ActivityClass.DNS_ANOMALY_TUNNELING.value, model.missing_classes)

        prob_dicts = model.predict_proba_dict(self.X)
        for d in prob_dicts:
            # Must contain entry for DNS_ANOMALY_TUNNELING with 0.0 probability
            self.assertIn(ActivityClass.DNS_ANOMALY_TUNNELING.value, d)
            self.assertAlmostEqual(d[ActivityClass.DNS_ANOMALY_TUNNELING.value], 0.0)
            # Total sum must still equal 1.0
            self.assertAlmostEqual(sum(d.values()), 1.0, places=5)


class TestArtifactSerialization(unittest.TestCase):
    def setUp(self):
        self.pipeline, self.raw_vectors, self.X, self.y, self.feature_names = (
            _create_sample_vectors_and_labels()
        )
        self.model = RandomForestActivityModel(random_state=42)
        self.model.fit(self.X, self.y, self.feature_names)
        self.transformer = self.pipeline.transformer

    def test_artifact_serialization_round_trip(self):
        artifact = build_classification_artifact(
            random_forest=self.model,
            transformer=self.transformer,
            hyperparameters=self.model.hyperparameters,
            random_state=42,
        )

        json_str = artifact.to_json()
        self.assertIn("CM-", json_str)
        self.assertIn(FEATURE_SCHEMA_VERSION, json_str)
        self.assertIn(LABEL_MAPPING_VERSION, json_str)

        loaded_art = ClassificationModelArtifact.from_json(json_str)
        self.assertEqual(loaded_art.model_id, artifact.model_id)

        loaded_model = loaded_art.load_random_forest()
        p1 = self.model.predict_proba_dict(self.X)
        p2 = loaded_model.predict_proba_dict(self.X)

        for row1, row2 in zip(p1, p2):
            for k in row1:
                self.assertAlmostEqual(row1[k], row2[k], places=7)


class TestInferenceAPI(unittest.TestCase):
    def setUp(self):
        self.pipeline, self.raw_vectors, self.X, self.y, self.feature_names = (
            _create_sample_vectors_and_labels()
        )
        self.model = RandomForestActivityModel(random_state=42)
        self.model.fit(self.X, self.y, self.feature_names)
        self.artifact = build_classification_artifact(
            random_forest=self.model,
            transformer=self.pipeline.transformer,
            hyperparameters=self.model.hyperparameters,
            random_state=42,
        )
        self.classifier = ActivityClassifier.from_artifact(self.artifact)

    def test_predict_feature_vector(self):
        pred = self.classifier.predict(self.raw_vectors[0])
        res = pred.result

        self.assertIsInstance(res.activity_class, ActivityClass)
        self.assertEqual(res.activity_class, pred.predicted_activity)
        self.assertGreaterEqual(res.confidence, 0.0)
        self.assertLessEqual(res.confidence, 1.0)
        self.assertEqual(set(res.class_probabilities.keys()), {ac.value for ac in ALL_ACTIVITY_CLASSES})
        self.assertAlmostEqual(sum(res.class_probabilities.values()), 1.0, places=4)

    def test_confidence_calculation(self):
        """Confidence must equal max(class_probabilities.values())."""
        pred = self.classifier.predict(self.raw_vectors[0])
        max_prob = max(pred.result.class_probabilities.values())
        self.assertAlmostEqual(pred.result.confidence, max_prob, places=6)

    def test_save_and_load_file(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "classifier.json"
            self.classifier.save(path)
            self.assertTrue(path.exists())

            loaded_cls = ActivityClassifier.load(path)
            res1 = self.classifier.predict(self.raw_vectors[0]).result
            res2 = loaded_cls.predict(self.raw_vectors[0]).result

            self.assertEqual(res1.activity_class, res2.activity_class)
            self.assertAlmostEqual(res1.confidence, res2.confidence, places=6)


class TestInferenceRejections(unittest.TestCase):
    def setUp(self):
        self.pipeline, self.raw_vectors, self.X, self.y, self.feature_names = (
            _create_sample_vectors_and_labels()
        )
        self.model = RandomForestActivityModel(random_state=42)
        self.model.fit(self.X, self.y, self.feature_names)
        self.artifact = build_classification_artifact(
            random_forest=self.model,
            transformer=self.pipeline.transformer,
            hyperparameters=self.model.hyperparameters,
            random_state=42,
        )
        self.classifier = ActivityClassifier.from_artifact(self.artifact)

    def test_schema_mismatch_rejection(self):
        bad_vector = FeatureVector(
            acquisition_id=ACQ_ID,
            schema_version="0.9-OLD",
            features=self.raw_vectors[0].features,
        )
        with self.assertRaises(SchemaVersionMismatchError):
            self.classifier.predict(bad_vector)

    def test_unknown_feature_rejection(self):
        empty_vector = FeatureVector(
            acquisition_id=ACQ_ID,
            schema_version=FEATURE_SCHEMA_VERSION,
            features=[],
        )
        with self.assertRaises(MissingFeatureError):
            self.classifier.predict(empty_vector)


class TestEvaluatorAndMetrics(unittest.TestCase):
    def test_evaluation_metrics(self):
        y_true = [
            ActivityClass.BENIGN,
            ActivityClass.BENIGN,
            ActivityClass.SCANNING_RECONNAISSANCE,
            ActivityClass.C2_MALWARE_COMMUNICATION,
        ]
        y_pred = [
            ActivityClass.BENIGN,
            ActivityClass.BENIGN,
            ActivityClass.SCANNING_RECONNAISSANCE,
            ActivityClass.C2_MALWARE_COMMUNICATION,
        ]

        report = evaluate_classifier(y_true, y_pred)
        self.assertEqual(report.accuracy, 1.0)
        self.assertEqual(report.macro_f1, 1.0)
        self.assertEqual(report.weighted_f1, 1.0)
        self.assertEqual(report.balanced_accuracy, 1.0)
        self.assertEqual(len(report.confusion_matrix), len(ALL_ACTIVITY_CLASSES))


class TestLeakageAndSafety(unittest.TestCase):
    def test_label_leakage(self):
        clean_features = {"flow_rate": 10.0, "byte_count": 500.0}
        validate_label_leakage(clean_features)

        leaky_features = {"flow_rate": 10.0, "activity_class": "BENIGN"}
        from backend.app.engines.analysis.features.validation import FeatureValidationError

        with self.assertRaises(FeatureValidationError):
            validate_label_leakage(leaky_features)

    def test_identifier_leakage(self):
        clean_dict = {"flow_count": 5.0, "unique_ips": 2.0}
        validate_identifier_leakage(clean_dict)

        leaky_dict = {"flow_count": 5.0, "src_ip": 12345.0}
        from backend.app.engines.analysis.features.validation import FeatureValidationError

        with self.assertRaises(FeatureValidationError):
            validate_identifier_leakage(leaky_dict)

    def test_temporal_split(self):
        self.assertTrue(validate_temporal_split("Monday-WorkingHours.csv", "train"))
        self.assertTrue(validate_temporal_split("Tuesday-WorkingHours.csv", "train"))
        self.assertTrue(validate_temporal_split("Wednesday-workingHours.csv", "train"))
        self.assertTrue(validate_temporal_split("Thursday-WorkingHours-Morning-WebAttacks.csv", "validation"))
        self.assertTrue(validate_temporal_split("Friday-WorkingHours-Afternoon-DDos.csv", "test"))


if __name__ == "__main__":
    unittest.main()
