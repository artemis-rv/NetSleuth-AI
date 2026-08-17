"""
analysis.py
-----------
M2 V1 Contract: Analysis Engine output types.

This module defines the authoritative Python-typed contract for M2's
internal and output objects consumed downstream by M3.

OWNERSHIP:
  - Contract definition: shared (all members)
  - Implementation: M2 (analysis engine)

CONTRACT VERSION: 1.0

M2 produces a FindingsPackage containing one or more Finding objects.
Each Finding describes a detected behavioral activity observed in a
NetworkIntelligencePackage.

M2 MUST NOT contain:
  - MITRE ATT&CK IDs, technique IDs, or tactic names
  - Attack chain objects
  - Investigation logic
  - Threat-intelligence or reputation data
  - External API references

Those responsibilities belong to M3 (Correlation & Investigation).

Do NOT modify another member's contract fields without a team interface
discussion and explicit agreement.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator, model_validator


# ---------------------------------------------------------------------------
# CONTRACT VERSION
# ---------------------------------------------------------------------------

M2_CONTRACT_VERSION = "1.0"


# ---------------------------------------------------------------------------
# ACTIVITY TAXONOMY  (M2 V1 — behavioral classes only, NOT MITRE)
# ---------------------------------------------------------------------------


class ActivityClass(str, Enum):
    """M2 V1 canonical activity taxonomy.

    These are behavioral observation labels produced by the M2 activity
    classifier.  They are NOT MITRE ATT&CK techniques or tactics.
    MITRE mapping is the exclusive responsibility of M3.
    """

    BENIGN = "BENIGN"
    C2_MALWARE_COMMUNICATION = "C2_MALWARE_COMMUNICATION"
    DNS_ANOMALY_TUNNELING = "DNS_ANOMALY_TUNNELING"
    SCANNING_RECONNAISSANCE = "SCANNING_RECONNAISSANCE"
    POSSIBLE_EXFILTRATION = "POSSIBLE_EXFILTRATION"
    SUSPICIOUS_WEB_ACTIVITY = "SUSPICIOUS_WEB_ACTIVITY"


# ---------------------------------------------------------------------------
# FEATURE VECTOR
# ---------------------------------------------------------------------------


class FeatureValue(BaseModel):
    """A single named feature value with metadata.

    Typed as float for continuous features, str for categorical ones.
    Missing values must be represented by setting present=False rather
    than inventing substitute values.
    """

    name: str = Field(..., description="Canonical feature name (use FeatureName enum)")
    value: Optional[float | str] = Field(
        None, description="Feature value; None when the feature is absent"
    )
    present: bool = Field(
        True, description="False when the source data did not contain this feature"
    )
    categorical: bool = Field(
        False, description="True when value encodes a category, not a measurement"
    )

    model_config = {"frozen": True, "extra": "forbid"}

    @model_validator(mode="after")
    def _absent_implies_none(self) -> "FeatureValue":
        if not self.present and self.value is not None:
            raise ValueError("present=False requires value=None")
        return self


class FeatureVector(BaseModel):
    """Ordered collection of FeatureValues for one analysis window.

    A FeatureVector is derived from a NetworkIntelligencePackage by the
    M2 feature extraction + engineering pipeline.  It is versioned so
    that model training artefacts can be tied to a specific schema version.
    """

    vector_id: str = Field(
        default_factory=lambda: f"FV-{uuid4().hex[:12].upper()}",
        description="Unique feature vector identifier",
    )
    acquisition_id: str = Field(..., description="Source acquisition identifier")
    schema_version: str = Field(
        default=M2_CONTRACT_VERSION,
        description="Feature schema version this vector conforms to",
    )
    features: list[FeatureValue] = Field(
        default_factory=list,
        description="Ordered list of feature values in canonical schema order",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when the vector was constructed",
    )

    model_config = {"frozen": True, "extra": "forbid"}

    def as_numeric_dict(self) -> dict[str, Optional[float]]:
        """Return {name: value} for all non-categorical present features."""
        return {
            fv.name: (fv.value if isinstance(fv.value, (int, float)) else None)
            for fv in self.features
            if not fv.categorical
        }

    def feature_names(self) -> list[str]:
        return [fv.name for fv in self.features]

    def features_as_dict(self) -> dict[str, Any]:
        """Return {name: value} for ALL features including categoricals."""
        return {fv.name: fv.value for fv in self.features}

    def get_feature_by_name(self, name: str) -> Optional["FeatureValue"]:
        """Return the FeatureValue for the given name, or None if absent."""
        for fv in self.features:
            if fv.name == name:
                return fv
        return None


# ---------------------------------------------------------------------------
# ANOMALY RESULT
# ---------------------------------------------------------------------------


class AnomalyResult(BaseModel):
    """Output of the M2 unsupervised anomaly model.

    score is bounded [0.0, 1.0].  Higher values indicate greater
    deviation from baseline behaviour.  The threshold used at inference
    time is captured for reproducibility.
    """

    anomaly_detected: bool = Field(
        ..., description="True when score >= threshold at inference time"
    )
    score: float = Field(..., ge=0.0, le=1.0, description="Anomaly score [0.0, 1.0]")
    threshold: float = Field(
        ..., ge=0.0, le=1.0, description="Decision threshold used at inference time"
    )
    model_id: str = Field(..., description="Identifier of the model that produced this result")
    model_version: str = Field(..., description="Version of the model")
    contributing_features: list[str] = Field(
        default_factory=list,
        description="Feature names that most influenced the score",
    )

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("score")
    @classmethod
    def _score_finite(cls, v: float) -> float:
        import math
        if not math.isfinite(v):
            raise ValueError(f"score must be finite, got {v}")
        return v

    @field_validator("threshold")
    @classmethod
    def _threshold_finite(cls, v: float) -> float:
        import math
        if not math.isfinite(v):
            raise ValueError(f"threshold must be finite, got {v}")
        return v


# ---------------------------------------------------------------------------
# CLASSIFICATION RESULT
# ---------------------------------------------------------------------------


class ClassificationResult(BaseModel):
    """Output of the M2 supervised activity classifier.

    confidence is bounded [0.0, 1.0].
    class_probabilities maps each ActivityClass to a probability; values
    must sum to approximately 1.0 (±1e-6 tolerance).
    """

    activity_class: ActivityClass = Field(..., description="Predicted activity class")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Confidence in the predicted class [0.0, 1.0]"
    )
    class_probabilities: dict[str, float] = Field(
        default_factory=dict,
        description="Probability per ActivityClass label",
    )
    model_id: str = Field(..., description="Identifier of the classifier model")
    model_version: str = Field(..., description="Version of the classifier model")

    model_config = {"frozen": True, "extra": "forbid"}

    @property
    def predicted_activity(self) -> ActivityClass:
        """Alias for activity_class."""
        return self.activity_class

    @field_validator("confidence")
    @classmethod
    def _confidence_finite(cls, v: float) -> float:
        import math
        if not math.isfinite(v):
            raise ValueError(f"confidence must be finite, got {v}")
        return v

    @model_validator(mode="after")
    def _probabilities_sum(self) -> "ClassificationResult":
        if self.class_probabilities:
            total = sum(self.class_probabilities.values())
            if abs(total - 1.0) > 1e-4:
                raise ValueError(
                    f"class_probabilities must sum to 1.0, got {total:.6f}"
                )
        return self


# ---------------------------------------------------------------------------
# EVIDENCE REFERENCE
# ---------------------------------------------------------------------------


class EvidenceReference(BaseModel):
    """Traceability link from a Finding back to M1 source objects.

    A Finding MUST carry at least one EvidenceReference.
    References must point to real M1 objects; do not invent IDs.
    """

    flow_ids: list[str] = Field(
        default_factory=list, description="Flow IDs from M1 that support this finding"
    )
    event_ids: list[str] = Field(
        default_factory=list,
        description="ProtocolEvent IDs from M1 that support this finding",
    )
    artifact_ids: list[str] = Field(
        default_factory=list,
        description="Artifact IDs from M1 that support this finding",
    )
    rationale: str = Field(
        ...,
        description="Human-readable explanation of why this evidence supports the finding",
    )

    model_config = {"frozen": True, "extra": "forbid"}


# ---------------------------------------------------------------------------
# FINDING
# ---------------------------------------------------------------------------


class Finding(BaseModel):
    """A single M2 analysis conclusion for one acquisition.

    A Finding encodes:
      - what activity was observed (activity_class)
      - how confident M2 is (classification_confidence)
      - how anomalous the behaviour is (anomaly_score, anomaly_detected)
      - an overall risk score
      - traceability back to M1 objects (evidence_references)
      - a snapshot of the features used (feature_snapshot)

    Finding MUST NOT contain:
      - mitre_id
      - technique / tactic
      - attack_chain
      - investigation conclusions
      - external threat intelligence
    """

    finding_id: str = Field(
        default_factory=lambda: f"F-{uuid4().hex[:12].upper()}",
        description="Unique finding identifier",
    )
    acquisition_id: str = Field(..., description="Source acquisition identifier")
    activity_class: ActivityClass = Field(
        ..., description="Detected behavioral activity class"
    )
    anomaly_score: float = Field(
        ..., ge=0.0, le=1.0, description="Anomaly score from the unsupervised model [0.0, 1.0]"
    )
    anomaly_detected: bool = Field(
        ..., description="True when the anomaly model flagged this acquisition"
    )
    classification_confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Confidence of the activity classifier [0.0, 1.0]",
    )
    risk_score: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Composite risk score computed by M2 [0.0, 1.0]",
    )
    evidence_references: list[EvidenceReference] = Field(
        ...,
        min_length=1,
        description="At least one M1 traceability reference is required",
    )
    feature_snapshot: dict[str, Any] = Field(
        default_factory=dict,
        description="Subset of feature values used for this finding (for auditability)",
    )
    anomaly_result: Optional[AnomalyResult] = Field(
        None, description="Full anomaly result if available"
    )
    classification_result: Optional[ClassificationResult] = Field(
        None, description="Full classification result if available"
    )
    decision_state: Optional[str] = Field(
        None, description="M2 Phase 7 decision state string"
    )
    feature_schema_version: Optional[str] = Field(
        None, description="Feature schema version"
    )
    anomaly_model_version: Optional[str] = Field(
        None, description="Anomaly model version"
    )
    classifier_model_version: Optional[str] = Field(
        None, description="Classifier model version"
    )
    observation_start: Optional[datetime] = Field(
        None, description="Start UTC timestamp of observation window"
    )
    observation_end: Optional[datetime] = Field(
        None, description="End UTC timestamp of observation window"
    )
    model_version: str = Field(
        ..., description="M2 analysis engine version that produced this finding"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of finding creation",
    )

    model_config = {"frozen": True, "extra": "forbid"}

    @field_validator("anomaly_score", "classification_confidence", "risk_score")
    @classmethod
    def _scores_finite(cls, v: float) -> float:
        import math
        if not math.isfinite(v):
            raise ValueError(f"Score fields must be finite, got {v}")
        return v


# ---------------------------------------------------------------------------
# FINDINGS PACKAGE
# ---------------------------------------------------------------------------


class FindingsPackage(BaseModel):
    """The M2 output package consumed by M3.

    Contains all Findings produced for one analysis run over one
    NetworkIntelligencePackage.

    This package MUST NOT contain MITRE identifiers, attack chain
    objects, investigation conclusions, or correlation data.
    """

    package_id: str = Field(
        default_factory=lambda: f"FP-{uuid4().hex[:12].upper()}",
        description="Unique package identifier",
    )
    contract_version: str = Field(
        default=M2_CONTRACT_VERSION,
        description="Contract version this package conforms to",
    )
    acquisition_id: str = Field(
        ..., description="Acquisition this package covers"
    )
    source_package_id: str = Field(
        ..., description="NetworkIntelligencePackage ID that was analysed"
    )
    findings: list[Finding] = Field(
        default_factory=list,
        description="All findings produced for this acquisition",
    )
    analysis_engine_version: str = Field(
        ..., description="M2 engine version string"
    )
    feature_schema_version: Optional[str] = Field(
        None, description="Feature schema version"
    )
    anomaly_model_version: Optional[str] = Field(
        None, description="Anomaly model version"
    )
    classifier_model_version: Optional[str] = Field(
        None, description="Classifier model version"
    )
    analysed_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp when analysis completed",
    )

    model_config = {"frozen": True, "extra": "forbid"}
