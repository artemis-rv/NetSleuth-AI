"""
temporal_features.py
--------------------
Extracts M2 temporal features from a NetworkIntelligencePackage.
"""

from __future__ import annotations

import statistics

from app.contracts.network_intelligence import NetworkIntelligencePackage
from app.contracts.analysis import FeatureValue
from app.contracts.feature_schema import FeatureName


def extract_temporal_features(package: NetworkIntelligencePackage) -> list[FeatureValue]:
    """Calculate temporal features.
    
    Args:
        package: The M1 observation package.
        
    Returns:
        List of computed FeatureValue objects.
    """
    flows = package.flows
    events = package.protocol_events
    
    # We need timestamps to calculate duration and rates
    timestamps = [f.timestamp for f in flows] + [e.timestamp for e in events]
    
    if not timestamps:
        return _build_empty_temporal_features()
        
    start_time = min(timestamps)
    end_time = max(timestamps)
    
    duration_seconds = (end_time - start_time).total_seconds()
    
    # Avoid division by zero
    safe_duration = max(duration_seconds, 1.0)
    
    event_rate = len(events) / safe_duration
    flow_rate = len(flows) / safe_duration
    
    dns_count = sum(1 for e in events if e.protocol == "dns")
    http_count = sum(1 for e in events if e.protocol == "http")
    tls_count = sum(1 for e in events if e.protocol in ("tls", "ssl"))
    
    dns_rate = dns_count / safe_duration
    http_rate = http_count / safe_duration
    tls_rate = tls_count / safe_duration
    
    # Calculate flow inter-arrival times
    flow_timestamps = sorted([f.timestamp for f in flows])
    interarrivals = []
    for i in range(1, len(flow_timestamps)):
        delta = (flow_timestamps[i] - flow_timestamps[i-1]).total_seconds()
        interarrivals.append(delta)
        
    mean_iat = statistics.mean(interarrivals) if interarrivals else None
    std_iat = statistics.stdev(interarrivals) if len(interarrivals) > 1 else None
    
    # CV = std / mean
    cv_iat = None
    if mean_iat is not None and std_iat is not None and mean_iat > 0:
        cv_iat = std_iat / mean_iat
        
    # Periodicity score (heuristic based on CV)
    # If CV is very low (e.g. < 0.1), inter-arrival is highly periodic (score approaches 1.0)
    # If CV is high (e.g. > 1.0), it's bursty/random (score approaches 0.0)
    periodicity_score = None
    if cv_iat is not None:
        periodicity_score = max(0.0, 1.0 - cv_iat)

    return [
        FeatureValue(name=FeatureName.TEMPORAL_OBSERVATION_DURATION.value, value=float(duration_seconds)),
        FeatureValue(name=FeatureName.TEMPORAL_EVENT_RATE.value, value=float(event_rate)),
        FeatureValue(name=FeatureName.TEMPORAL_FLOW_RATE.value, value=float(flow_rate)),
        FeatureValue(name=FeatureName.TEMPORAL_DNS_RATE.value, value=float(dns_rate)),
        FeatureValue(name=FeatureName.TEMPORAL_HTTP_RATE.value, value=float(http_rate)),
        FeatureValue(name=FeatureName.TEMPORAL_TLS_RATE.value, value=float(tls_rate)),
        FeatureValue(name=FeatureName.TEMPORAL_PERIODICITY_SCORE.value, value=periodicity_score, present=periodicity_score is not None),
        FeatureValue(name=FeatureName.TEMPORAL_INTERARRIVAL_MEAN.value, value=mean_iat, present=mean_iat is not None),
        FeatureValue(name=FeatureName.TEMPORAL_INTERARRIVAL_STD.value, value=std_iat, present=std_iat is not None),
        FeatureValue(name=FeatureName.TEMPORAL_INTERARRIVAL_CV.value, value=cv_iat, present=cv_iat is not None),
    ]


def _build_empty_temporal_features() -> list[FeatureValue]:
    return [
        FeatureValue(name=FeatureName.TEMPORAL_OBSERVATION_DURATION.value, value=0.0),
        FeatureValue(name=FeatureName.TEMPORAL_EVENT_RATE.value, value=0.0),
        FeatureValue(name=FeatureName.TEMPORAL_FLOW_RATE.value, value=0.0),
        FeatureValue(name=FeatureName.TEMPORAL_DNS_RATE.value, value=0.0),
        FeatureValue(name=FeatureName.TEMPORAL_HTTP_RATE.value, value=0.0),
        FeatureValue(name=FeatureName.TEMPORAL_TLS_RATE.value, value=0.0),
        FeatureValue(name=FeatureName.TEMPORAL_PERIODICITY_SCORE.value, value=None, present=False),
        FeatureValue(name=FeatureName.TEMPORAL_INTERARRIVAL_MEAN.value, value=None, present=False),
        FeatureValue(name=FeatureName.TEMPORAL_INTERARRIVAL_STD.value, value=None, present=False),
        FeatureValue(name=FeatureName.TEMPORAL_INTERARRIVAL_CV.value, value=None, present=False),
    ]
