"""
dns_features.py
---------------
Extracts M2 DNS features from a NetworkIntelligencePackage.
"""

from __future__ import annotations

import statistics

from backend.app.contracts.network_intelligence import NetworkIntelligencePackage, DNSData
from backend.app.contracts.analysis import FeatureValue
from backend.app.contracts.feature_schema import FeatureName


def extract_dns_features(package: NetworkIntelligencePackage) -> list[FeatureValue]:
    """Calculate DNS features.
    
    Args:
        package: The M1 observation package.
        
    Returns:
        List of computed FeatureValue objects.
    """
    # Extract only DNS protocol events
    dns_events = [
        event for event in package.protocol_events 
        if event.protocol == "dns" and isinstance(event.protocol_data, DNSData)
    ]
    
    count = len(dns_events)
    if count == 0:
        return _build_empty_dns_features()
        
    unique_domains = set()
    unique_query_types = set()
    unique_answer_ips = set()
    
    nxdomain_count = 0
    total_answers = 0
    
    domain_lengths = []
    label_lengths = []
    subdomain_depths = []
    
    # Map DNS events back to source IP via their parent flow
    # Build a lookup of flow_id -> source IP
    flow_src_map = {f.flow_id: f.source.ip for f in package.flows}
    domains_per_source: dict[str, set[str]] = {}
    
    for event in dns_events:
        data: DNSData = event.protocol_data
        query = data.query
        
        if query:
            unique_domains.add(query)
            domain_lengths.append(len(query))
            
            labels = query.split(".")
            for label in labels:
                if label:
                    label_lengths.append(len(label))
            
            # depth is dots minus 1, but typical subdomain depth:
            # e.g., google.com (depth 0), www.google.com (depth 1)
            # A simple metric is number of dots
            subdomain_depths.append(max(0, len(labels) - 2))
            
            # Map query to source IP
            src_ip = flow_src_map.get(event.flow_id)
            if src_ip:
                if src_ip not in domains_per_source:
                    domains_per_source[src_ip] = set()
                domains_per_source[src_ip].add(query)
                
        if data.query_type:
            unique_query_types.add(data.query_type)
            
        if data.response_code == "NXDOMAIN":
            nxdomain_count += 1
            
        if data.answers:
            total_answers += len(data.answers)
            for ans in data.answers:
                # We assume answers might contain IPs, just add them to cardinality set
                # Not doing strict IP parsing here, just counting unique answer strings
                unique_answer_ips.add(ans)

    mean_domain_len = statistics.mean(domain_lengths) if domain_lengths else None
    max_domain_len = max(domain_lengths) if domain_lengths else None
    
    mean_label_len = statistics.mean(label_lengths) if label_lengths else None
    max_label_len = max(label_lengths) if label_lengths else None
    
    mean_depth = statistics.mean(subdomain_depths) if subdomain_depths else None
    
    nxdomain_ratio = nxdomain_count / count
    
    src_ip_count = len(domains_per_source)
    unique_domains_per_src = (
        sum(len(ds) for ds in domains_per_source.values()) / src_ip_count
    ) if src_ip_count > 0 else 0.0

    return [
        FeatureValue(name=FeatureName.DNS_QUERY_COUNT.value, value=float(count)),
        FeatureValue(name=FeatureName.DNS_UNIQUE_DOMAINS.value, value=float(len(unique_domains))),
        FeatureValue(name=FeatureName.DNS_UNIQUE_QUERY_TYPES.value, value=float(len(unique_query_types))),
        FeatureValue(name=FeatureName.DNS_NXDOMAIN_RATIO.value, value=float(nxdomain_ratio)),
        FeatureValue(name=FeatureName.DNS_ANSWER_COUNT.value, value=float(total_answers)),
        FeatureValue(name=FeatureName.DNS_UNIQUE_ANSWER_IPS.value, value=float(len(unique_answer_ips))),
        FeatureValue(name=FeatureName.DNS_MEAN_DOMAIN_LENGTH.value, value=mean_domain_len, present=mean_domain_len is not None),
        FeatureValue(name=FeatureName.DNS_MAX_DOMAIN_LENGTH.value, value=max_domain_len, present=max_domain_len is not None),
        FeatureValue(name=FeatureName.DNS_MEAN_LABEL_LENGTH.value, value=mean_label_len, present=mean_label_len is not None),
        FeatureValue(name=FeatureName.DNS_MAX_LABEL_LENGTH.value, value=max_label_len, present=max_label_len is not None),
        FeatureValue(name=FeatureName.DNS_SUBDOMAIN_DEPTH.value, value=mean_depth, present=mean_depth is not None),
        FeatureValue(name=FeatureName.DNS_UNIQUE_DOMAINS_PER_SOURCE.value, value=float(unique_domains_per_src)),
    ]


def _build_empty_dns_features() -> list[FeatureValue]:
    return [
        FeatureValue(name=FeatureName.DNS_QUERY_COUNT.value, value=0.0),
        FeatureValue(name=FeatureName.DNS_UNIQUE_DOMAINS.value, value=0.0),
        FeatureValue(name=FeatureName.DNS_UNIQUE_QUERY_TYPES.value, value=0.0),
        FeatureValue(name=FeatureName.DNS_NXDOMAIN_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.DNS_ANSWER_COUNT.value, value=0.0),
        FeatureValue(name=FeatureName.DNS_UNIQUE_ANSWER_IPS.value, value=0.0),
        FeatureValue(name=FeatureName.DNS_MEAN_DOMAIN_LENGTH.value, value=None, present=False),
        FeatureValue(name=FeatureName.DNS_MAX_DOMAIN_LENGTH.value, value=None, present=False),
        FeatureValue(name=FeatureName.DNS_MEAN_LABEL_LENGTH.value, value=None, present=False),
        FeatureValue(name=FeatureName.DNS_MAX_LABEL_LENGTH.value, value=None, present=False),
        FeatureValue(name=FeatureName.DNS_SUBDOMAIN_DEPTH.value, value=None, present=False),
        FeatureValue(name=FeatureName.DNS_UNIQUE_DOMAINS_PER_SOURCE.value, value=0.0),
    ]
