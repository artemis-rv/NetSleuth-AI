"""
risk.py
-------
M2 Phase 7 — Deterministic Risk Engine.

Calculates composite behavioral risk scores combining anomaly magnitude, activity class
severity, classification confidence, evidence volume, and temporal persistence.

IMPORTANT: Risk is NOT equivalent to anomaly_score (risk != anomaly_score).
"""

from __future__ import annotations

import math
from typing import Optional

from app.contracts.analysis import ActivityClass, FeatureVector

# ---------------------------------------------------------------------------
# ACTIVITY SEVERITY WEIGHTS
# ---------------------------------------------------------------------------
# Base severity weight per ActivityClass taxonomy member [0.0, 1.0]
ACTIVITY_SEVERITY_WEIGHTS: dict[ActivityClass, float] = {
    ActivityClass.BENIGN: 0.0,
    ActivityClass.SCANNING_RECONNAISSANCE: 0.4,
    ActivityClass.SUSPICIOUS_WEB_ACTIVITY: 0.6,
    ActivityClass.DNS_ANOMALY_TUNNELING: 0.8,
    ActivityClass.C2_MALWARE_COMMUNICATION: 0.9,
    ActivityClass.POSSIBLE_EXFILTRATION: 1.0,
}


def extract_evidence_volume_score(vector: FeatureVector) -> float:
    """Extract normalized evidence volume score in [0.0, 1.0] from FeatureVector."""
    num_dict = vector.as_numeric_dict()

    # Look up byte and packet volume features
    orig_bytes = float(num_dict.get("orig_bytes") or num_dict.get("total_bytes") or 0.0)
    resp_bytes = float(num_dict.get("resp_bytes") or 0.0)
    total_bytes = orig_bytes + resp_bytes

    orig_pkts = float(num_dict.get("orig_packets") or num_dict.get("total_packets") or 0.0)
    flow_count = float(num_dict.get("flow_count") or 1.0)

    # Log1p normalized volume scores
    bytes_norm = min(1.0, math.log1p(total_bytes) / 15.0)  # ~3.2MB max scale
    pkts_norm = min(1.0, math.log1p(orig_pkts) / 10.0)     # ~22k pkts max scale
    flows_norm = min(1.0, math.log1p(flow_count) / 7.0)

    vol = 0.5 * bytes_norm + 0.3 * pkts_norm + 0.2 * flows_norm
    return float(np.clip(vol, 0.0, 1.0)) if "np" in globals() else max(0.0, min(1.0, vol))


def extract_temporal_persistence_score(vector: FeatureVector) -> float:
    """Extract normalized temporal persistence score in [0.0, 1.0] from FeatureVector."""
    num_dict = vector.as_numeric_dict()

    duration = float(num_dict.get("duration_seconds") or num_dict.get("duration") or 0.0)
    flow_rate = float(num_dict.get("flow_rate_per_sec") or 0.0)

    dur_norm = min(1.0, math.log1p(duration) / 8.0)        # ~3000s max scale
    rate_norm = min(1.0, math.log1p(flow_rate) / 5.0)

    persistence = 0.7 * dur_norm + 0.3 * rate_norm
    return max(0.0, min(1.0, persistence))


def calculate_risk_score(
    *,
    anomaly_score: float,
    predicted_activity: ActivityClass,
    confidence: float,
    feature_vector: Optional[FeatureVector] = None,
) -> float:
    """Calculate deterministic composite risk score in [0.0, 1.0].

    Risk combines:
      1. Anomaly magnitude (anomaly_score)
      2. Activity class behavioral severity (ACTIVITY_SEVERITY_WEIGHTS)
      3. Classification confidence
      4. Evidence volume
      5. Temporal persistence

    Formula:
      - For BENIGN predicted class:
        risk = 0.6 * anomaly_score * (1.0 - 0.5 * confidence) + 0.4 * volume * persistence * anomaly_score
      - For Non-Benign predicted class:
        base_threat = severity * (0.3 + 0.7 * confidence)
        risk = 0.55 * base_threat + 0.25 * anomaly_score + 0.10 * volume + 0.10 * persistence

    Args:
        anomaly_score: Anomaly score in [0.0, 1.0].
        predicted_activity: Predicted ActivityClass member.
        confidence: Classification confidence in [0.0, 1.0].
        feature_vector: Optional source FeatureVector for evidence volume & temporal persistence.

    Returns:
        Composite risk score float in [0.0, 1.0].
    """
    anom = max(0.0, min(1.0, float(anomaly_score)))
    conf = max(0.0, min(1.0, float(confidence)))
    severity = ACTIVITY_SEVERITY_WEIGHTS.get(predicted_activity, 0.5)

    vol = extract_evidence_volume_score(feature_vector) if feature_vector else 0.1
    pers = extract_temporal_persistence_score(feature_vector) if feature_vector else 0.1

    if predicted_activity == ActivityClass.BENIGN:
        # High anomaly in benign predicted class increases risk slightly as an unclassified anomaly,
        # but overall risk remains lower than malicious activity.
        raw_risk = 0.5 * anom * (1.0 - 0.4 * conf) + 0.3 * vol * anom + 0.2 * pers * anom
    else:
        # Threat component weighted by severity and confidence
        threat = severity * (0.4 + 0.6 * conf)
        raw_risk = 0.50 * threat + 0.30 * anom + 0.10 * vol + 0.10 * pers

    bounded = max(0.0, min(1.0, float(raw_risk)))
    if not math.isfinite(bounded):
        return 0.0

    return round(bounded, 6)
