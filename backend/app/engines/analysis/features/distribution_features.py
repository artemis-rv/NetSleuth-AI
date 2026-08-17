"""
distribution_features.py
------------------------
Extracts M2 distribution features (e.g. entropy) from a NetworkIntelligencePackage.
"""

from __future__ import annotations

import math
from collections import Counter
from typing import Sequence

from app.contracts.network_intelligence import NetworkIntelligencePackage, DNSData
from app.contracts.analysis import FeatureValue
from app.contracts.feature_schema import FeatureName


def _calculate_shannon_entropy(counts: Counter) -> float:
    """Calculate Shannon entropy for a distribution."""
    total = sum(counts.values())
    if total == 0:
        return 0.0
        
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
        
    return entropy


def extract_distribution_features(package: NetworkIntelligencePackage) -> list[FeatureValue]:
    """Calculate entropy and distribution features.
    
    Args:
        package: The M1 observation package.
        
    Returns:
        List of computed FeatureValue objects.
    """
    flows = package.flows
    events = package.protocol_events
    
    # Destination IP Entropy
    dst_ip_counts = Counter(f.destination.ip for f in flows)
    dst_ip_entropy = _calculate_shannon_entropy(dst_ip_counts)
    
    # Destination Port Entropy
    dst_port_counts = Counter(f.destination.port for f in flows)
    dst_port_entropy = _calculate_shannon_entropy(dst_port_counts)
    
    # Protocol Entropy (TCP vs UDP vs ICMP)
    proto_counts = Counter(f.protocol.lower() for f in flows)
    proto_entropy = _calculate_shannon_entropy(proto_counts)
    
    # Domain Name Entropy (DNS Queries)
    dns_events = [e.protocol_data for e in events if e.protocol == "dns" and isinstance(e.protocol_data, DNSData)]
    domain_counts = Counter(d.query for d in dns_events if d.query)
    domain_entropy = _calculate_shannon_entropy(domain_counts)

    return [
        FeatureValue(name=FeatureName.DIST_DESTINATION_ENTROPY.value, value=float(dst_ip_entropy)),
        FeatureValue(name=FeatureName.DIST_PORT_ENTROPY.value, value=float(dst_port_entropy)),
        FeatureValue(name=FeatureName.DIST_PROTOCOL_ENTROPY.value, value=float(proto_entropy)),
        FeatureValue(name=FeatureName.DIST_DOMAIN_ENTROPY.value, value=float(domain_entropy)),
    ]
