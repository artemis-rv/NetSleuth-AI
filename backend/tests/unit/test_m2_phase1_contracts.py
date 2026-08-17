"""
test_m2_phase1_contracts.py
----------------------------
M2 Phase 1 test suite.

Covers:
  1.  Model immutability
  2.  Unknown-field rejection where extra='forbid'
  3.  Feature schema determinism
  4.  FindingsPackage serialization / deserialization round-trip
  5.  M2 contracts contain no MITRE fields
  6.  AnomalyResult score bounds
  7.  ClassificationResult probability sum validation
  8.  FeatureValue absent-implies-None invariant
  9.  EvidenceReference required in Finding
  10. ActivityClass enum coverage
"""

import json
import math
import unittest
from datetime import datetime, timezone

from backend.app.contracts.analysis import (
    ActivityClass,
    AnomalyResult,
    ClassificationResult,
    EvidenceReference,
    FeatureValue,
    FeatureVector,
    Finding,
    FindingsPackage,
    M2_CONTRACT_VERSION,
)
from backend.app.contracts.feature_schema import (
    FEATURE_SCHEMA,
    FEATURE_SCHEMA_VERSION,
    FeatureName,
    schema_feature_names,
    schema_version,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_evidence_ref(**kwargs) -> EvidenceReference:
    defaults = dict(
        flow_ids=["F-001"],
        event_ids=[],
        artifact_ids=[],
        rationale="Test rationale",
    )
    defaults.update(kwargs)
    return EvidenceReference(**defaults)


def _make_finding(**kwargs) -> Finding:
    defaults = dict(
        acquisition_id="ACQ-TEST-001",
        activity_class=ActivityClass.BENIGN,
        anomaly_score=0.1,
        anomaly_detected=False,
        classification_confidence=0.9,
        risk_score=0.1,
        evidence_references=[_make_evidence_ref()],
        model_version="m2-v1.0-test",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def _make_findings_package(**kwargs) -> FindingsPackage:
    defaults = dict(
        acquisition_id="ACQ-TEST-001",
        source_package_id="NIP-TEST-001",
        analysis_engine_version="m2-v1.0-test",
    )
    defaults.update(kwargs)
    return FindingsPackage(**defaults)


# ---------------------------------------------------------------------------
# Test classes
# ---------------------------------------------------------------------------


class TestModelImmutability(unittest.TestCase):
    """Pydantic v2 frozen models must raise an error on attribute assignment."""

    def test_finding_immutable(self):
        f = _make_finding()
        with self.assertRaises(Exception):  # ValidationError or TypeError
            f.acquisition_id = "CHANGED"

    def test_findings_package_immutable(self):
        fp = _make_findings_package()
        with self.assertRaises(Exception):
            fp.acquisition_id = "CHANGED"

    def test_anomaly_result_immutable(self):
        ar = AnomalyResult(
            anomaly_detected=True,
            score=0.8,
            threshold=0.7,
            model_id="test",
            model_version="1.0",
        )
        with self.assertRaises(Exception):
            ar.score = 0.1

    def test_classification_result_immutable(self):
        probs = {c.value: 1.0 / 6 for c in ActivityClass}
        cr = ClassificationResult(
            activity_class=ActivityClass.BENIGN,
            confidence=0.9,
            class_probabilities=probs,
            model_id="test",
            model_version="1.0",
        )
        with self.assertRaises(Exception):
            cr.confidence = 0.1

    def test_feature_value_immutable(self):
        fv = FeatureValue(name=FeatureName.FLOW_COUNT.value, value=10.0)
        with self.assertRaises(Exception):
            fv.value = 99.0

    def test_feature_vector_immutable(self):
        vec = FeatureVector(acquisition_id="ACQ-001")
        with self.assertRaises(Exception):
            vec.acquisition_id = "CHANGED"

    def test_evidence_reference_immutable(self):
        ref = _make_evidence_ref()
        with self.assertRaises(Exception):
            ref.rationale = "CHANGED"


class TestUnknownFieldRejection(unittest.TestCase):
    """Models with extra='forbid' must reject unknown fields."""

    def test_feature_value_rejects_unknown(self):
        with self.assertRaises(Exception):
            FeatureValue(name=FeatureName.FLOW_COUNT.value, value=1.0, unknown_field="x")

    def test_anomaly_result_rejects_unknown(self):
        with self.assertRaises(Exception):
            AnomalyResult(
                anomaly_detected=False,
                score=0.2,
                threshold=0.5,
                model_id="m",
                model_version="1",
                mitre_id="T1234",  # MITRE must never appear
            )

    def test_finding_rejects_unknown(self):
        with self.assertRaises(Exception):
            Finding(
                acquisition_id="A",
                activity_class=ActivityClass.BENIGN,
                anomaly_score=0.0,
                anomaly_detected=False,
                classification_confidence=1.0,
                risk_score=0.0,
                evidence_references=[_make_evidence_ref()],
                model_version="1",
                mitre_technique="T1234",  # MITRE field — must be rejected
            )

    def test_findings_package_rejects_unknown(self):
        with self.assertRaises(Exception):
            FindingsPackage(
                acquisition_id="A",
                source_package_id="B",
                analysis_engine_version="1",
                attack_chain=[],  # must be rejected
            )

    def test_evidence_reference_rejects_unknown(self):
        with self.assertRaises(Exception):
            EvidenceReference(
                flow_ids=[],
                event_ids=[],
                artifact_ids=[],
                rationale="ok",
                extra_nonsense="bad",
            )

    def test_classification_result_rejects_unknown(self):
        with self.assertRaises(Exception):
            ClassificationResult(
                activity_class=ActivityClass.BENIGN,
                confidence=0.9,
                class_probabilities={},
                model_id="m",
                model_version="1",
                tactic="Discovery",  # MITRE field — must be rejected
            )


class TestFeatureSchemaDeterminism(unittest.TestCase):
    """The feature schema must produce the same output across multiple calls."""

    def test_feature_names_deterministic(self):
        names1 = schema_feature_names()
        names2 = schema_feature_names()
        self.assertEqual(names1, names2)

    def test_feature_names_are_strings(self):
        for n in schema_feature_names():
            self.assertIsInstance(n, str)

    def test_schema_version_constant(self):
        self.assertEqual(schema_version(), FEATURE_SCHEMA_VERSION)

    def test_all_enum_members_in_schema(self):
        for fn in FeatureName:
            self.assertIn(fn, FEATURE_SCHEMA, f"{fn} missing from FEATURE_SCHEMA")

    def test_schema_groups_are_valid(self):
        valid_groups = {
            "flow", "connection_behaviour", "dns", "http",
            "tls", "temporal", "distribution",
        }
        for fn, desc in FEATURE_SCHEMA.items():
            self.assertIn(desc.group, valid_groups, f"{fn} has invalid group '{desc.group}'")

    def test_feature_count_matches_enum(self):
        self.assertEqual(len(FEATURE_SCHEMA), len(FeatureName))

    def test_feature_names_list_length(self):
        self.assertEqual(len(schema_feature_names()), len(FeatureName))

    def test_schema_descriptor_names_match_enum(self):
        for fn, desc in FEATURE_SCHEMA.items():
            self.assertEqual(fn, desc.name)


class TestFindingsPackageSerialisation(unittest.TestCase):
    """FindingsPackage must round-trip through JSON without data loss."""

    def _build_full_package(self) -> FindingsPackage:
        probs = {c.value: 1.0 / len(ActivityClass) for c in ActivityClass}
        ar = AnomalyResult(
            anomaly_detected=True,
            score=0.85,
            threshold=0.7,
            model_id="zscore-v1",
            model_version="1.0",
            contributing_features=[FeatureName.FLOW_COUNT.value],
        )
        cr = ClassificationResult(
            activity_class=ActivityClass.SCANNING_RECONNAISSANCE,
            confidence=0.92,
            class_probabilities=probs,
            model_id="clf-v1",
            model_version="1.0",
        )
        finding = Finding(
            acquisition_id="ACQ-001",
            activity_class=ActivityClass.SCANNING_RECONNAISSANCE,
            anomaly_score=0.85,
            anomaly_detected=True,
            classification_confidence=0.92,
            risk_score=0.88,
            evidence_references=[
                EvidenceReference(
                    flow_ids=["F-001", "F-002"],
                    event_ids=["E-001"],
                    artifact_ids=["ART-001"],
                    rationale="Observed high-rate port sweep with failed connections",
                )
            ],
            feature_snapshot={
                FeatureName.FLOW_COUNT.value: 1500,
                FeatureName.CONN_FAILED_RATIO.value: 0.87,
            },
            anomaly_result=ar,
            classification_result=cr,
            model_version="m2-v1.0",
        )
        return FindingsPackage(
            acquisition_id="ACQ-001",
            source_package_id="NIP-001",
            findings=[finding],
            analysis_engine_version="m2-v1.0",
        )

    def test_round_trip_json(self):
        pkg = self._build_full_package()
        serialised = pkg.model_dump_json()
        deserialised = FindingsPackage.model_validate_json(serialised)
        self.assertEqual(pkg.package_id, deserialised.package_id)
        self.assertEqual(pkg.acquisition_id, deserialised.acquisition_id)
        self.assertEqual(len(pkg.findings), len(deserialised.findings))

    def test_round_trip_dict(self):
        pkg = self._build_full_package()
        d = pkg.model_dump()
        deserialised = FindingsPackage.model_validate(d)
        self.assertEqual(pkg.package_id, deserialised.package_id)
        self.assertEqual(
            pkg.findings[0].activity_class,
            deserialised.findings[0].activity_class,
        )

    def test_json_is_valid_json(self):
        pkg = self._build_full_package()
        raw = pkg.model_dump_json()
        parsed = json.loads(raw)
        self.assertIsInstance(parsed, dict)
        self.assertIn("package_id", parsed)
        self.assertIn("findings", parsed)

    def test_contract_version_preserved(self):
        pkg = self._build_full_package()
        d = pkg.model_dump()
        self.assertEqual(d["contract_version"], M2_CONTRACT_VERSION)

    def test_empty_findings_package(self):
        fp = _make_findings_package()
        raw = fp.model_dump_json()
        recovered = FindingsPackage.model_validate_json(raw)
        self.assertEqual(fp.package_id, recovered.package_id)
        self.assertEqual(recovered.findings, [])


class TestNoMITREFields(unittest.TestCase):
    """M2 contracts must not define any MITRE ATT&CK fields."""

    MITRE_FIELD_NAMES = {
        "mitre_id",
        "technique",
        "technique_id",
        "tactic",
        "tactic_id",
        "attack_chain",
        "attack_pattern",
        "mitre_technique",
        "mitre_tactic",
    }

    def _public_fields(self, model_class) -> set[str]:
        return set(model_class.model_fields.keys())

    def test_finding_has_no_mitre_fields(self):
        fields = self._public_fields(Finding)
        overlap = fields & self.MITRE_FIELD_NAMES
        self.assertSetEqual(overlap, set(), f"Finding has MITRE fields: {overlap}")

    def test_findings_package_has_no_mitre_fields(self):
        fields = self._public_fields(FindingsPackage)
        overlap = fields & self.MITRE_FIELD_NAMES
        self.assertSetEqual(overlap, set(), f"FindingsPackage has MITRE fields: {overlap}")

    def test_anomaly_result_has_no_mitre_fields(self):
        fields = self._public_fields(AnomalyResult)
        overlap = fields & self.MITRE_FIELD_NAMES
        self.assertSetEqual(overlap, set(), f"AnomalyResult has MITRE fields: {overlap}")

    def test_classification_result_has_no_mitre_fields(self):
        fields = self._public_fields(ClassificationResult)
        overlap = fields & self.MITRE_FIELD_NAMES
        self.assertSetEqual(overlap, set(), f"ClassificationResult has MITRE fields: {overlap}")

    def test_evidence_reference_has_no_mitre_fields(self):
        fields = self._public_fields(EvidenceReference)
        overlap = fields & self.MITRE_FIELD_NAMES
        self.assertSetEqual(overlap, set(), f"EvidenceReference has MITRE fields: {overlap}")

    def test_feature_vector_has_no_mitre_fields(self):
        fields = self._public_fields(FeatureVector)
        overlap = fields & self.MITRE_FIELD_NAMES
        self.assertSetEqual(overlap, set(), f"FeatureVector has MITRE fields: {overlap}")


class TestAnomalyResultBounds(unittest.TestCase):

    def test_score_below_zero_rejected(self):
        with self.assertRaises(Exception):
            AnomalyResult(anomaly_detected=False, score=-0.01, threshold=0.5,
                          model_id="m", model_version="1")

    def test_score_above_one_rejected(self):
        with self.assertRaises(Exception):
            AnomalyResult(anomaly_detected=True, score=1.01, threshold=0.5,
                          model_id="m", model_version="1")

    def test_score_nan_rejected(self):
        with self.assertRaises(Exception):
            AnomalyResult(anomaly_detected=False, score=float("nan"), threshold=0.5,
                          model_id="m", model_version="1")

    def test_score_inf_rejected(self):
        with self.assertRaises(Exception):
            AnomalyResult(anomaly_detected=False, score=float("inf"), threshold=0.5,
                          model_id="m", model_version="1")

    def test_valid_boundary_values(self):
        ar0 = AnomalyResult(anomaly_detected=False, score=0.0, threshold=0.5,
                            model_id="m", model_version="1")
        ar1 = AnomalyResult(anomaly_detected=True, score=1.0, threshold=0.5,
                            model_id="m", model_version="1")
        self.assertEqual(ar0.score, 0.0)
        self.assertEqual(ar1.score, 1.0)


class TestClassificationResultValidation(unittest.TestCase):

    def _valid_probs(self) -> dict[str, float]:
        classes = list(ActivityClass)
        return {c.value: 1.0 / len(classes) for c in classes}

    def test_valid_probabilities(self):
        cr = ClassificationResult(
            activity_class=ActivityClass.BENIGN,
            confidence=0.9,
            class_probabilities=self._valid_probs(),
            model_id="m",
            model_version="1",
        )
        self.assertIsNotNone(cr)

    def test_probabilities_not_summing_to_one_rejected(self):
        bad_probs = {c.value: 0.5 for c in ActivityClass}  # sums to 3.0
        with self.assertRaises(Exception):
            ClassificationResult(
                activity_class=ActivityClass.BENIGN,
                confidence=0.9,
                class_probabilities=bad_probs,
                model_id="m",
                model_version="1",
            )

    def test_empty_probabilities_allowed(self):
        # Empty dict skips the sum check (no probabilities provided)
        cr = ClassificationResult(
            activity_class=ActivityClass.BENIGN,
            confidence=0.9,
            class_probabilities={},
            model_id="m",
            model_version="1",
        )
        self.assertEqual(cr.class_probabilities, {})

    def test_confidence_nan_rejected(self):
        with self.assertRaises(Exception):
            ClassificationResult(
                activity_class=ActivityClass.BENIGN,
                confidence=float("nan"),
                class_probabilities={},
                model_id="m",
                model_version="1",
            )


class TestFeatureValueInvariant(unittest.TestCase):

    def test_present_false_requires_none_value(self):
        with self.assertRaises(Exception):
            FeatureValue(
                name=FeatureName.FLOW_COUNT.value,
                value=10.0,
                present=False,
            )

    def test_present_false_with_none_is_valid(self):
        fv = FeatureValue(
            name=FeatureName.FLOW_COUNT.value,
            value=None,
            present=False,
        )
        self.assertFalse(fv.present)
        self.assertIsNone(fv.value)

    def test_present_true_with_value(self):
        fv = FeatureValue(name=FeatureName.FLOW_COUNT.value, value=42.0)
        self.assertTrue(fv.present)
        self.assertEqual(fv.value, 42.0)

    def test_present_true_with_none_allowed(self):
        # A present feature may still have None value (e.g. not computable)
        fv = FeatureValue(name=FeatureName.FLOW_COUNT.value, value=None, present=True)
        self.assertTrue(fv.present)


class TestFindingEvidenceRequired(unittest.TestCase):

    def test_finding_requires_evidence_reference(self):
        with self.assertRaises(Exception):
            Finding(
                acquisition_id="A",
                activity_class=ActivityClass.BENIGN,
                anomaly_score=0.0,
                anomaly_detected=False,
                classification_confidence=1.0,
                risk_score=0.0,
                evidence_references=[],  # empty — must fail
                model_version="1",
            )

    def test_finding_with_one_reference_valid(self):
        f = _make_finding()
        self.assertEqual(len(f.evidence_references), 1)


class TestActivityClassCoverage(unittest.TestCase):

    EXPECTED_CLASSES = {
        "BENIGN",
        "C2_MALWARE_COMMUNICATION",
        "DNS_ANOMALY_TUNNELING",
        "SCANNING_RECONNAISSANCE",
        "POSSIBLE_EXFILTRATION",
        "SUSPICIOUS_WEB_ACTIVITY",
    }

    def test_all_required_classes_present(self):
        actual = {c.value for c in ActivityClass}
        self.assertSetEqual(actual, self.EXPECTED_CLASSES)

    def test_no_extra_classes(self):
        actual = {c.value for c in ActivityClass}
        extra = actual - self.EXPECTED_CLASSES
        self.assertSetEqual(extra, set(), f"Unexpected ActivityClass values: {extra}")

    def test_each_class_usable_in_finding(self):
        for ac in ActivityClass:
            f = _make_finding(activity_class=ac)
            self.assertEqual(f.activity_class, ac)


class TestFeatureVectorNumericDict(unittest.TestCase):

    def test_numeric_dict_excludes_categorical(self):
        fvs = [
            FeatureValue(name=FeatureName.FLOW_COUNT.value, value=10.0),
            FeatureValue(
                name=FeatureName.TLS_VERSION_DISTRIBUTION.value,
                value='{"TLSv1.3": 5}',
                categorical=True,
            ),
        ]
        vec = FeatureVector(acquisition_id="A", features=fvs)
        nd = vec.as_numeric_dict()
        self.assertIn(FeatureName.FLOW_COUNT.value, nd)
        self.assertNotIn(FeatureName.TLS_VERSION_DISTRIBUTION.value, nd)

    def test_feature_names_list(self):
        fvs = [
            FeatureValue(name=FeatureName.FLOW_COUNT.value, value=5.0),
            FeatureValue(name=FeatureName.FLOW_TOTAL_BYTES.value, value=1024.0),
        ]
        vec = FeatureVector(acquisition_id="A", features=fvs)
        names = vec.feature_names()
        self.assertEqual(names, [FeatureName.FLOW_COUNT.value, FeatureName.FLOW_TOTAL_BYTES.value])


if __name__ == "__main__":
    unittest.main(verbosity=2)
