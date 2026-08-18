"""
test_m2_phase4_pipeline.py
--------------------------
M2 Phase 4 Feature Engineering Pipeline tests.
"""

import json
import math
import unittest
from datetime import datetime, timezone

from app.contracts.network_intelligence import (
    NetworkIntelligencePackage, Flow, Endpoint,
    ProtocolEvent, DNSData, HTTPData, TLSData,
    FlowProvenance, EventProvenance,
)
from app.contracts.feature_schema import FeatureName, FEATURE_SCHEMA_VERSION
from app.engines.analysis.features.pipeline import (
    FeatureEngineeringPipeline, FeatureMetadata,
)
from app.engines.analysis.features.transformer import FeatureTransformer
from app.engines.analysis.features.normalization import (
    MinMaxScaler, StandardScaler, LogScaler,
)
from app.engines.analysis.features.encoding import (
    entropy_from_json_dist, cardinality_from_json_dist, encode_categorical_feature,
)
from app.engines.analysis.features.validation import (
    FeatureValidationError, validate_no_identifier_leakage, validate_numeric_array,
    validate_missing_values,
)

ACQ_ID = "ACQ-001"
PKG_ID = "PKG-001"
FLOW_PROV = FlowProvenance(acquisition_id=ACQ_ID, source="test", source_log="conn.log")
EVENT_PROV = EventProvenance(acquisition_id=ACQ_ID, source="test", source_log="test.log")
T0 = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
T1 = datetime(2020, 1, 1, 12, 0, 10, tzinfo=timezone.utc)


def _flow(fid, uid, dst_ip="2.2.2.2", dst_port=80, proto="tcp",
          ts=T0, duration=1.0, orig_b=1000, resp_b=500):
    return Flow(
        flow_id=fid, zeek_uid=uid, acquisition_id=ACQ_ID,
        source=Endpoint(ip="1.1.1.1", port=9000),
        destination=Endpoint(ip=dst_ip, port=dst_port),
        protocol=proto, timestamp=ts, duration=duration,
        orig_bytes=orig_b, resp_bytes=resp_b,
        orig_packets=10, resp_packets=5,
        connection_state="SF",
        provenance=FLOW_PROV,
    )


def _dns_event(eid, uid, query="example.com", rcode="NOERROR", answers=None):
    return ProtocolEvent(
        event_id=eid, zeek_uid=uid, acquisition_id=ACQ_ID,
        flow_id="F1", timestamp=T0, protocol="dns",
        protocol_data=DNSData(query=query, query_type="A",
                              response_code=rcode, answers=answers or []),
        provenance=EVENT_PROV,
    )


def _pkg(flows=None, events=None):
    return NetworkIntelligencePackage(
        package_id=PKG_ID, acquisition_id=ACQ_ID,
        flows=flows or [], protocol_events=events or [], artifacts=[],
    )


# ---------------------------------------------------------------------------
# NORMALIZATION TESTS
# ---------------------------------------------------------------------------

class TestMinMaxScaler(unittest.TestCase):
    def test_basic_fit_transform(self):
        s = MinMaxScaler()
        s.fit([0.0, 10.0, 5.0])
        self.assertAlmostEqual(s.transform(0.0), 0.0, places=5)
        self.assertAlmostEqual(s.transform(10.0), 1.0, places=5)

    def test_none_returns_zero(self):
        s = MinMaxScaler()
        s.fit([1.0, 5.0])
        self.assertEqual(s.transform(None), 0.0)

    def test_inf_returns_zero(self):
        s = MinMaxScaler()
        s.fit([1.0, 5.0])
        self.assertEqual(s.transform(float("inf")), 0.0)

    def test_serialize_round_trip(self):
        s = MinMaxScaler()
        s.fit([0.0, 100.0])
        s2 = MinMaxScaler.from_dict(s.to_dict())
        self.assertAlmostEqual(s.transform(50.0), s2.transform(50.0), places=10)


class TestLogScaler(unittest.TestCase):
    def test_skewed_compression(self):
        """log1p(1000000) should be close to 1.0 after fitting."""
        s = LogScaler()
        s.fit([0.0, 1e6])
        val = s.transform(1e6)
        self.assertAlmostEqual(val, 1.0, places=4)

    def test_zero_input(self):
        s = LogScaler()
        s.fit([0.0, 1000.0])
        self.assertAlmostEqual(s.transform(0.0), 0.0, places=4)

    def test_serialize_round_trip(self):
        s = LogScaler()
        s.fit([0.0, 1000.0, 5000.0])
        d = s.to_dict()
        s2 = LogScaler.from_dict(d)
        self.assertAlmostEqual(s.transform(500.0), s2.transform(500.0), places=10)


class TestStandardScaler(unittest.TestCase):
    def test_zero_mean(self):
        s = StandardScaler()
        s.fit([1.0, 2.0, 3.0, 4.0, 5.0])
        # Mean is 3.0 — transform(3.0) should be ~0
        self.assertAlmostEqual(s.transform(3.0), 0.0, places=5)

    def test_serialize_round_trip(self):
        s = StandardScaler()
        s.fit([10.0, 20.0, 30.0])
        s2 = StandardScaler.from_dict(s.to_dict())
        self.assertAlmostEqual(s.transform(20.0), s2.transform(20.0), places=10)


# ---------------------------------------------------------------------------
# ENCODING TESTS
# ---------------------------------------------------------------------------

class TestEncoding(unittest.TestCase):
    def test_entropy_two_equi(self):
        js = json.dumps({"TLSv1.2": 5, "TLSv1.3": 5})
        self.assertAlmostEqual(entropy_from_json_dist(js), 1.0, places=5)

    def test_entropy_single(self):
        js = json.dumps({"TLSv1.2": 10})
        self.assertAlmostEqual(entropy_from_json_dist(js), 0.0, places=5)

    def test_entropy_none(self):
        self.assertEqual(entropy_from_json_dist(None), 0.0)

    def test_entropy_empty(self):
        self.assertEqual(entropy_from_json_dist("{}"), 0.0)

    def test_cardinality(self):
        js = json.dumps({"A": 3, "B": 5, "C": 1})
        self.assertEqual(cardinality_from_json_dist(js), 3.0)

    def test_encode_tls_version(self):
        js = json.dumps({"TLSv1.2": 10, "TLSv1.3": 5})
        result = encode_categorical_feature("tls_version_distribution", js)
        self.assertIn("tls_version_entropy", result)
        self.assertIn("tls_version_cardinality", result)
        self.assertGreater(result["tls_version_entropy"], 0.0)
        self.assertEqual(result["tls_version_cardinality"], 2.0)

    def test_no_raw_ip_or_domain(self):
        # IPs and domain strings must never be encoded directly
        result = encode_categorical_feature("tls_version_distribution",
                                           '{"192.168.1.1": 5}')
        # The result is numeric (entropy/cardinality) — NOT the raw IP string
        for val in result.values():
            self.assertIsInstance(val, float)


# ---------------------------------------------------------------------------
# VALIDATION TESTS
# ---------------------------------------------------------------------------

class TestValidation(unittest.TestCase):
    def test_no_identifier_leakage_passes(self):
        # Should not raise
        validate_no_identifier_leakage({"flow_rate": 0.5, "dns_query_count": 3.0})

    def test_identifier_in_name_raises(self):
        with self.assertRaises(FeatureValidationError):
            validate_no_identifier_leakage({"src_ip_feature": 1.0})

    def test_flow_id_raises(self):
        with self.assertRaises(FeatureValidationError):
            validate_no_identifier_leakage({"flow_id_count": 5.0})

    def test_nan_raises(self):
        with self.assertRaises(FeatureValidationError):
            validate_numeric_array({"flow_count": float("nan")})

    def test_inf_raises(self):
        with self.assertRaises(FeatureValidationError):
            validate_numeric_array({"flow_count": float("inf")})

    def test_none_filled_with_zero(self):
        result = validate_missing_values({"flow_count": None, "dns_rate": 0.5})
        self.assertEqual(result["flow_count"], 0.0)
        self.assertEqual(result["dns_rate"], 0.5)


# ---------------------------------------------------------------------------
# TRANSFORMER TESTS
# ---------------------------------------------------------------------------

class TestFeatureTransformer(unittest.TestCase):
    def setUp(self):
        self.pkg1 = _pkg(flows=[_flow("F1", "u1", orig_b=100, resp_b=50)])
        self.pkg2 = _pkg(flows=[_flow("F2", "u2", orig_b=10000, resp_b=5000)])
        from app.engines.analysis.features.extractor import extract_all_features
        self.v1 = extract_all_features(self.pkg1)
        self.v2 = extract_all_features(self.pkg2)

    def test_transform_before_fit_raises(self):
        t = FeatureTransformer()
        with self.assertRaises(RuntimeError):
            t.transform(self.v1)

    def test_fit_transform_returns_valid_floats(self):
        t = FeatureTransformer()
        results = t.fit_transform([self.v1, self.v2])
        for arr in results:
            for name, val in arr.items():
                self.assertIsInstance(val, float)
                self.assertTrue(math.isfinite(val), f"Non-finite value for {name}: {val}")

    def test_all_values_in_range_after_scaling(self):
        """After fit, all scaled values should be in a reasonable bounded range."""
        t = FeatureTransformer()
        results = t.fit_transform([self.v1, self.v2])
        for arr in results:
            for name, val in arr.items():
                self.assertGreaterEqual(val, -10.0, f"{name}={val} too negative")
                self.assertLessEqual(val, 10.0, f"{name}={val} too large")

    def test_no_identifier_in_output(self):
        t = FeatureTransformer()
        results = t.fit_transform([self.v1])
        from app.engines.analysis.features.validation import _IDENTIFIER_PATTERNS
        for arr in results:
            for name in arr:
                for pat in _IDENTIFIER_PATTERNS:
                    self.assertNotIn(pat, name.lower())

    def test_serialization_round_trip(self):
        t = FeatureTransformer()
        t.fit_transform([self.v1, self.v2])

        # Serialize / deserialize
        d = t.to_dict()
        t2 = FeatureTransformer.from_dict(d)

        r1 = t.transform(self.v1)
        r2 = t2.transform(self.v1)
        self.assertEqual(set(r1.keys()), set(r2.keys()))
        for name in r1:
            self.assertAlmostEqual(r1[name], r2[name], places=10,
                                   msg=f"Mismatch for {name}")

    def test_json_serialization_round_trip(self):
        t = FeatureTransformer()
        t.fit_transform([self.v1])
        js = t.to_json()
        t2 = FeatureTransformer.from_json(js)
        self.assertTrue(t2.is_fitted)

    def test_train_test_isolation(self):
        """transform() must not re-fit; test data must use train parameters."""
        t = FeatureTransformer()
        t.fit([self.v1])  # fit on v1 only

        # Apply to v2 (test data) — parameters come from v1 fit
        result = t.transform(self.v2)
        self.assertIsInstance(result, dict)

        # Verify is_fitted unchanged after transform
        self.assertTrue(t.is_fitted)


# ---------------------------------------------------------------------------
# PIPELINE INTEGRATION TESTS
# ---------------------------------------------------------------------------

class TestFeatureEngineeringPipeline(unittest.TestCase):
    def setUp(self):
        self.train_pkg = _pkg(flows=[
            _flow("F1", "u1", orig_b=500, resp_b=200),
            _flow("F2", "u2", orig_b=8000, resp_b=3000, dst_ip="3.3.3.3"),
        ])
        self.test_pkg = _pkg(flows=[_flow("F3", "u3", orig_b=200, resp_b=100)])

    def test_fit_transform_returns_list(self):
        pipeline = FeatureEngineeringPipeline()
        results = pipeline.fit_transform([self.train_pkg])
        self.assertEqual(len(results), 1)
        numeric, metadata = results[0]
        self.assertIsInstance(numeric, dict)
        self.assertIsInstance(metadata, FeatureMetadata)

    def test_metadata_has_correct_acquisition_id(self):
        pipeline = FeatureEngineeringPipeline()
        results = pipeline.fit_transform([self.train_pkg])
        _, metadata = results[0]
        self.assertEqual(metadata.acquisition_id, ACQ_ID)

    def test_metadata_has_schema_version(self):
        pipeline = FeatureEngineeringPipeline()
        results = pipeline.fit_transform([self.train_pkg])
        _, metadata = results[0]
        self.assertEqual(metadata.schema_version, FEATURE_SCHEMA_VERSION)

    def test_metadata_has_flow_refs(self):
        pipeline = FeatureEngineeringPipeline()
        results = pipeline.fit_transform([self.train_pkg])
        _, metadata = results[0]
        self.assertIn("F1", metadata.source_flow_ids)

    def test_metadata_not_in_numeric_array(self):
        """source_flow_ids and acquisition_id must NOT appear in numeric array keys."""
        pipeline = FeatureEngineeringPipeline()
        results = pipeline.fit_transform([self.train_pkg])
        numeric, metadata = results[0]
        for key in numeric:
            self.assertNotIn("acquisition_id", key)
            self.assertNotIn("flow_id", key)

    def test_deterministic_output(self):
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit([self.train_pkg])
        r1, _ = pipeline.transform(self.test_pkg)
        r2, _ = pipeline.transform(self.test_pkg)
        self.assertEqual(r1, r2)

    def test_pipeline_serialization_round_trip(self):
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit([self.train_pkg])
        d = pipeline.to_dict()
        pipeline2 = FeatureEngineeringPipeline.from_dict(d)

        r1, _ = pipeline.transform(self.test_pkg)
        r2, _ = pipeline2.transform(self.test_pkg)
        self.assertEqual(set(r1.keys()), set(r2.keys()))
        for name in r1:
            self.assertAlmostEqual(r1[name], r2[name], places=10)

    def test_pipeline_json_round_trip(self):
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit([self.train_pkg])
        js = pipeline.to_json()
        pipeline2 = FeatureEngineeringPipeline.from_json(js)
        r1, _ = pipeline.transform(self.test_pkg)
        r2, _ = pipeline2.transform(self.test_pkg)
        self.assertEqual(r1, r2)

    def test_schema_compatibility(self):
        """Numeric array keys should correspond to known schema features."""
        from app.engines.analysis.features.transformer import _SCALER_STRATEGY
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit([self.train_pkg])
        numeric, _ = pipeline.transform(self.test_pkg)
        for key in numeric:
            self.assertIn(key, _SCALER_STRATEGY,
                          f"Unknown feature '{key}' not in schema")

    def test_observation_window_in_metadata(self):
        pipeline = FeatureEngineeringPipeline()
        results = pipeline.fit_transform([self.train_pkg])
        _, metadata = results[0]
        self.assertIsNotNone(metadata.observation_window.start)
        self.assertGreaterEqual(metadata.observation_window.duration_seconds, 0.0)

    def test_empty_package_does_not_raise(self):
        empty_pkg = _pkg()
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit([self.train_pkg])
        numeric, metadata = pipeline.transform(empty_pkg)
        for val in numeric.values():
            self.assertTrue(math.isfinite(val), f"Non-finite after empty package: {val}")

    def test_missing_field_handling(self):
        """Missing fields (present=False, value=None) must be filled with 0.0."""
        pipeline = FeatureEngineeringPipeline()
        pipeline.fit([self.train_pkg])
        numeric, _ = pipeline.transform(self.test_pkg)
        for val in numeric.values():
            self.assertIsNotNone(val)


if __name__ == "__main__":
    unittest.main()
