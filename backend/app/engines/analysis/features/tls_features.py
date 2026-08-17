"""
tls_features.py
---------------
Extracts M2 TLS features from a NetworkIntelligencePackage.
"""

from __future__ import annotations

import json
import statistics
from collections import Counter

from backend.app.contracts.network_intelligence import NetworkIntelligencePackage, TLSData
from backend.app.contracts.analysis import FeatureValue
from backend.app.contracts.feature_schema import FeatureName


def extract_tls_features(package: NetworkIntelligencePackage) -> list[FeatureValue]:
    """Calculate TLS features.
    
    Args:
        package: The M1 observation package.
        
    Returns:
        List of computed FeatureValue objects.
    """
    tls_events = [
        event for event in package.protocol_events 
        if event.protocol in ("tls", "ssl") and isinstance(event.protocol_data, TLSData)
    ]
    
    count = len(tls_events)
    if count == 0:
        return _build_empty_tls_features()
        
    unique_sni = set()
    missing_sni_count = 0
    
    version_counts = Counter()
    cipher_counts = Counter()
    cert_validity_days = []
    
    # Track unique destination IPs for TLS connections
    flow_dst_map = {f.flow_id: f.destination.ip for f in package.flows}
    unique_destinations = set()
    
    for event in tls_events:
        data: TLSData = event.protocol_data
        
        if data.server_name:
            unique_sni.add(data.server_name)
        else:
            missing_sni_count += 1
            
        if data.version:
            version_counts[data.version] += 1
            
        if data.cipher:
            cipher_counts[data.cipher] += 1
            
        if data.not_valid_before and data.not_valid_after:
            validity_duration = data.not_valid_after - data.not_valid_before
            cert_validity_days.append(validity_duration.total_seconds() / 86400.0)
            
        dst_ip = flow_dst_map.get(event.flow_id)
        if dst_ip:
            unique_destinations.add(dst_ip)
            
    missing_sni_ratio = missing_sni_count / count
    mean_validity = statistics.mean(cert_validity_days) if cert_validity_days else None
    
    version_dist_json = json.dumps(dict(version_counts))
    cipher_dist_json = json.dumps(dict(cipher_counts))

    return [
        FeatureValue(name=FeatureName.TLS_CONNECTION_COUNT.value, value=float(count)),
        FeatureValue(name=FeatureName.TLS_UNIQUE_SNI.value, value=float(len(unique_sni))),
        FeatureValue(
            name=FeatureName.TLS_VERSION_DISTRIBUTION.value, 
            value=version_dist_json, 
            categorical=True
        ),
        FeatureValue(
            name=FeatureName.TLS_CIPHER_DISTRIBUTION.value, 
            value=cipher_dist_json, 
            categorical=True
        ),
        FeatureValue(name=FeatureName.TLS_MISSING_SNI_RATIO.value, value=float(missing_sni_ratio)),
        FeatureValue(name=FeatureName.TLS_CERT_VALIDITY_DURATION.value, value=mean_validity, present=mean_validity is not None),
        FeatureValue(name=FeatureName.TLS_UNIQUE_DESTINATIONS.value, value=float(len(unique_destinations))),
    ]


def _build_empty_tls_features() -> list[FeatureValue]:
    return [
        FeatureValue(name=FeatureName.TLS_CONNECTION_COUNT.value, value=0.0),
        FeatureValue(name=FeatureName.TLS_UNIQUE_SNI.value, value=0.0),
        FeatureValue(name=FeatureName.TLS_VERSION_DISTRIBUTION.value, value="{}", categorical=True),
        FeatureValue(name=FeatureName.TLS_CIPHER_DISTRIBUTION.value, value="{}", categorical=True),
        FeatureValue(name=FeatureName.TLS_MISSING_SNI_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.TLS_CERT_VALIDITY_DURATION.value, value=None, present=False),
        FeatureValue(name=FeatureName.TLS_UNIQUE_DESTINATIONS.value, value=0.0),
    ]
