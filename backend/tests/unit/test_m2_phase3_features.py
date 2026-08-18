"""
test_m2_phase3_features.py
--------------------------
M2 Phase 3 Feature Extraction module tests.
"""

import unittest
from datetime import datetime, timezone

from app.contracts.network_intelligence import (
    NetworkIntelligencePackage,
    Flow,
    Endpoint,
    ProtocolEvent,
    DNSData,
    HTTPData,
    TLSData,
    FlowProvenance,
    EventProvenance,
)
from app.contracts.feature_schema import FeatureName
from app.engines.analysis.features.extractor import extract_all_features

ACQ_ID = "ACQ-123"
PKG_ID = "PKG-123"
FLOW_PROV = FlowProvenance(acquisition_id=ACQ_ID, source="test", source_log="conn.log")
EVENT_PROV = EventProvenance(acquisition_id=ACQ_ID, source="test", source_log="test.log")


def _make_flow(flow_id, uid, src_ip, src_port, dst_ip, dst_port, proto,
               ts, duration=None, orig_b=None, resp_b=None,
               orig_p=None, resp_p=None, state="SF"):
    return Flow(
        flow_id=flow_id,
        zeek_uid=uid,
        acquisition_id=ACQ_ID,
        source=Endpoint(ip=src_ip, port=src_port),
        destination=Endpoint(ip=dst_ip, port=dst_port),
        protocol=proto,
        timestamp=ts,
        duration=duration,
        orig_bytes=orig_b,
        resp_bytes=resp_b,
        orig_packets=orig_p,
        resp_packets=resp_p,
        connection_state=state,
        provenance=FLOW_PROV,
    )


def _make_dns_event(event_id, uid, flow_id, ts, query, qtype, rcode, answers):
    return ProtocolEvent(
        event_id=event_id,
        zeek_uid=uid,
        acquisition_id=ACQ_ID,
        flow_id=flow_id,
        timestamp=ts,
        protocol="dns",
        protocol_data=DNSData(query=query, query_type=qtype, response_code=rcode, answers=answers),
        provenance=EVENT_PROV,
    )


def _make_http_event(event_id, uid, flow_id, ts, method, host, uri, status, ua, req_b=None, resp_b=None):
    return ProtocolEvent(
        event_id=event_id,
        zeek_uid=uid,
        acquisition_id=ACQ_ID,
        flow_id=flow_id,
        timestamp=ts,
        protocol="http",
        protocol_data=HTTPData(method=method, host=host, uri=uri, status_code=status,
                               user_agent=ua, request_body_len=req_b, response_body_len=resp_b),
        provenance=EVENT_PROV,
    )


def _make_tls_event(event_id, uid, flow_id, ts, sni, version, cipher):
    return ProtocolEvent(
        event_id=event_id,
        zeek_uid=uid,
        acquisition_id=ACQ_ID,
        flow_id=flow_id,
        timestamp=ts,
        protocol="tls",
        protocol_data=TLSData(server_name=sni, version=version, cipher=cipher),
        provenance=EVENT_PROV,
    )


def _make_package(flows=None, events=None):
    return NetworkIntelligencePackage(
        package_id=PKG_ID,
        acquisition_id=ACQ_ID,
        flows=flows or [],
        protocol_events=events or [],
        artifacts=[],
    )


class TestFeatureExtraction(unittest.TestCase):

    def test_empty_package(self):
        """Empty package: all count features zero, all nullable missing features absent."""
        pkg = _make_package()
        vector = extract_all_features(pkg)
        features = vector.features_as_dict()

        self.assertEqual(features[FeatureName.FLOW_COUNT.value], 0.0)
        self.assertEqual(features[FeatureName.DNS_QUERY_COUNT.value], 0.0)
        self.assertEqual(features[FeatureName.HTTP_REQUEST_COUNT.value], 0.0)
        self.assertEqual(features[FeatureName.TLS_CONNECTION_COUNT.value], 0.0)
        self.assertEqual(features[FeatureName.TEMPORAL_OBSERVATION_DURATION.value], 0.0)

        # Missing value invariant: present=False → value=None
        for f in vector.features:
            if not f.present:
                self.assertIsNone(f.value)

    def test_flow_features(self):
        t0 = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2020, 1, 1, 12, 0, 1, tzinfo=timezone.utc)
        f1 = _make_flow("F1", "u1", "1.1.1.1", 1000, "2.2.2.2", 80, "tcp",
                        t0, duration=1.5, orig_b=100, resp_b=200, orig_p=2, resp_p=3, state="SF")
        f2 = _make_flow("F2", "u2", "1.1.1.1", 1001, "3.3.3.3", 53, "udp",
                        t1, duration=0.5, orig_b=50, resp_b=0, orig_p=1, resp_p=0, state="REJ")

        pkg = _make_package(flows=[f1, f2])
        features = extract_all_features(pkg).features_as_dict()

        self.assertEqual(features[FeatureName.FLOW_COUNT.value], 2.0)
        self.assertEqual(features[FeatureName.FLOW_UNIQUE_SOURCE_IPS.value], 1.0)
        self.assertEqual(features[FeatureName.FLOW_UNIQUE_DESTINATION_IPS.value], 2.0)
        self.assertEqual(features[FeatureName.FLOW_UNIQUE_DESTINATION_PORTS.value], 2.0)
        self.assertEqual(features[FeatureName.FLOW_TCP_COUNT.value], 1.0)
        self.assertEqual(features[FeatureName.FLOW_UDP_COUNT.value], 1.0)
        self.assertEqual(features[FeatureName.FLOW_TOTAL_BYTES.value], 350.0)
        self.assertEqual(features[FeatureName.FLOW_MEAN_DURATION.value], 1.0)
        self.assertEqual(features[FeatureName.CONN_SHORT_RATIO.value], 0.5)   # 1/2 short
        self.assertEqual(features[FeatureName.CONN_FAILED_RATIO.value], 0.5)  # 1/2 REJ

    def test_missing_dns(self):
        """No DNS events → all DNS counts zero, nullable absent."""
        pkg = _make_package()
        features = extract_all_features(pkg).features_as_dict()
        self.assertEqual(features[FeatureName.DNS_QUERY_COUNT.value], 0.0)
        self.assertIsNone(features[FeatureName.DNS_MEAN_DOMAIN_LENGTH.value])

    def test_dns_features(self):
        t0 = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2020, 1, 1, 12, 0, 1, tzinfo=timezone.utc)
        f1 = _make_flow("F1", "u1", "1.1.1.1", 1000, "8.8.8.8", 53, "udp",
                        t0, duration=0.1, state="SF")
        e1 = _make_dns_event("E1", "u1", "F1", t0, "www.google.com", "A", "NOERROR", ["8.8.8.8"])
        e2 = _make_dns_event("E2", "u1", "F1", t1, "bad.domain", "A", "NXDOMAIN", [])

        pkg = _make_package(flows=[f1], events=[e1, e2])
        features = extract_all_features(pkg).features_as_dict()

        self.assertEqual(features[FeatureName.DNS_QUERY_COUNT.value], 2.0)
        self.assertEqual(features[FeatureName.DNS_UNIQUE_DOMAINS.value], 2.0)
        self.assertEqual(features[FeatureName.DNS_NXDOMAIN_RATIO.value], 0.5)
        self.assertEqual(features[FeatureName.DNS_ANSWER_COUNT.value], 1.0)
        self.assertEqual(features[FeatureName.DNS_MEAN_DOMAIN_LENGTH.value], 12.0)  # (14+10)/2
        self.assertEqual(features[FeatureName.DIST_DOMAIN_ENTROPY.value], 1.0)  # 2 equi-freq

    def test_missing_http(self):
        """No HTTP events → all HTTP counts zero."""
        pkg = _make_package()
        features = extract_all_features(pkg).features_as_dict()
        self.assertEqual(features[FeatureName.HTTP_REQUEST_COUNT.value], 0.0)

    def test_http_features(self):
        t0 = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2020, 1, 1, 12, 0, 1, tzinfo=timezone.utc)
        e1 = _make_http_event("E1", "u1", "F1", t0, "GET", "example.com",
                              "/index.html", 200, "Mozilla/5.0", resp_b=500)
        e2 = _make_http_event("E2", "u2", "F1", t1, "POST", "example.com",
                              "/login", 401, None, req_b=100)

        pkg = _make_package(events=[e1, e2])
        features = extract_all_features(pkg).features_as_dict()

        self.assertEqual(features[FeatureName.HTTP_REQUEST_COUNT.value], 2.0)
        self.assertEqual(features[FeatureName.HTTP_GET_RATIO.value], 0.5)
        self.assertEqual(features[FeatureName.HTTP_POST_RATIO.value], 0.5)
        self.assertEqual(features[FeatureName.HTTP_ERROR_STATUS_RATIO.value], 0.5)
        self.assertEqual(features[FeatureName.HTTP_MISSING_USER_AGENT_RATIO.value], 0.5)
        self.assertEqual(features[FeatureName.HTTP_DOWNLOAD_BYTES.value], 500.0)
        self.assertEqual(features[FeatureName.HTTP_UPLOAD_BYTES.value], 100.0)

    def test_missing_tls(self):
        """No TLS events → all TLS counts zero."""
        pkg = _make_package()
        features = extract_all_features(pkg).features_as_dict()
        self.assertEqual(features[FeatureName.TLS_CONNECTION_COUNT.value], 0.0)

    def test_tls_features(self):
        t0 = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2020, 1, 1, 12, 0, 1, tzinfo=timezone.utc)
        e1 = _make_tls_event("E1", "u1", "F1", t0, "example.com", "TLSv1.2",
                             "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256")
        e2 = _make_tls_event("E2", "u2", "F1", t1, None, "TLSv1.2",
                             "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")

        pkg = _make_package(events=[e1, e2])
        vector = extract_all_features(pkg)
        features = vector.features_as_dict()

        self.assertEqual(features[FeatureName.TLS_CONNECTION_COUNT.value], 2.0)
        self.assertEqual(features[FeatureName.TLS_MISSING_SNI_RATIO.value], 0.5)

        v_dist = vector.get_feature_by_name(FeatureName.TLS_VERSION_DISTRIBUTION.value)
        self.assertIsNotNone(v_dist)
        self.assertTrue(v_dist.categorical)
        self.assertIn("TLSv1.2", v_dist.value)

    def test_temporal_features(self):
        # 3 flows spaced 5s apart → window=10s, IAT mean=5s, IAT std=0s, CV=0, periodicity=1.0
        t0 = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2020, 1, 1, 12, 0, 5, tzinfo=timezone.utc)
        t2 = datetime(2020, 1, 1, 12, 0, 10, tzinfo=timezone.utc)
        f1 = _make_flow("F1", "u1", "1.1.1.1", 1, "2.2.2.2", 80, "tcp", t0, duration=0)
        f2 = _make_flow("F2", "u2", "1.1.1.1", 1, "2.2.2.2", 80, "tcp", t1, duration=0)
        f3 = _make_flow("F3", "u3", "1.1.1.1", 1, "2.2.2.2", 80, "tcp", t2, duration=0)

        pkg = _make_package(flows=[f1, f2, f3])
        features = extract_all_features(pkg).features_as_dict()

        self.assertEqual(features[FeatureName.TEMPORAL_OBSERVATION_DURATION.value], 10.0)
        self.assertAlmostEqual(features[FeatureName.TEMPORAL_FLOW_RATE.value], 0.3)
        self.assertEqual(features[FeatureName.TEMPORAL_INTERARRIVAL_MEAN.value], 5.0)
        self.assertEqual(features[FeatureName.TEMPORAL_INTERARRIVAL_STD.value], 0.0)
        self.assertEqual(features[FeatureName.TEMPORAL_INTERARRIVAL_CV.value], 0.0)
        self.assertEqual(features[FeatureName.TEMPORAL_PERIODICITY_SCORE.value], 1.0)

    def test_deterministic_output(self):
        """Same package → same feature values both times (IDs differ, values match)."""
        f1 = _make_flow("F1", "u1", "1.1.1.1", 1000, "2.2.2.2", 80, "tcp",
                        datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc), duration=1.0)
        pkg = _make_package(flows=[f1])

        d1 = extract_all_features(pkg).features_as_dict()
        d2 = extract_all_features(pkg).features_as_dict()
        self.assertEqual(d1, d2)

    def test_provenance_preservation(self):
        """acquisition_id must be preserved on the resulting FeatureVector."""
        pkg = _make_package()
        vector = extract_all_features(pkg)
        self.assertEqual(vector.acquisition_id, ACQ_ID)

    def test_no_identifier_leakage(self):
        """Feature names must not contain raw IPs, UIDs, flow_ids, or event_ids."""
        forbidden_prefixes = {"1.1.1.1", "2.2.2.2", "u1", "F1", "E1", "ACQ-123", "PKG-123"}
        f1 = _make_flow("F1", "u1", "1.1.1.1", 1000, "2.2.2.2", 80, "tcp",
                        datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc))
        pkg = _make_package(flows=[f1])
        vector = extract_all_features(pkg)
        for fv in vector.features:
            for forbidden in forbidden_prefixes:
                self.assertNotIn(forbidden, fv.name,
                    f"Identifier leak: '{forbidden}' found in feature name '{fv.name}'")

    def test_multiple_flows(self):
        """Vector must contain features from all flows combined."""
        t0 = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        flows = [
            _make_flow(f"F{i}", f"u{i}", "1.1.1.1", i, "2.2.2.2", 80, "tcp", t0)
            for i in range(5)
        ]
        pkg = _make_package(flows=flows)
        features = extract_all_features(pkg).features_as_dict()
        self.assertEqual(features[FeatureName.FLOW_COUNT.value], 5.0)

    def test_temporal_ordering(self):
        """Feature extraction must not depend on the order flows are provided."""
        t0 = datetime(2020, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
        t1 = datetime(2020, 1, 1, 12, 0, 5, tzinfo=timezone.utc)
        f1 = _make_flow("F1", "u1", "1.1.1.1", 1, "2.2.2.2", 80, "tcp", t0)
        f2 = _make_flow("F2", "u2", "1.1.1.1", 1, "2.2.2.2", 80, "tcp", t1)

        pkg_a = _make_package(flows=[f1, f2])
        pkg_b = _make_package(flows=[f2, f1])  # reversed order

        da = extract_all_features(pkg_a).features_as_dict()
        db = extract_all_features(pkg_b).features_as_dict()
        self.assertEqual(da, db)


if __name__ == "__main__":
    unittest.main()
