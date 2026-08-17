"""
flow_features.py
----------------
Extracts M2 flow and connection behavior features from a NetworkIntelligencePackage.
"""

from __future__ import annotations

import statistics
from typing import Optional

from app.contracts.network_intelligence import NetworkIntelligencePackage, Flow
from app.contracts.analysis import FeatureValue
from app.contracts.feature_schema import FeatureName


def extract_flow_features(package: NetworkIntelligencePackage) -> list[FeatureValue]:
    """Calculate flow and connection behavior features.
    
    Args:
        package: The M1 observation package.
        
    Returns:
        List of computed FeatureValue objects.
    """
    flows = package.flows
    count = len(flows)
    
    if count == 0:
        return _build_empty_flow_features()
        
    # --- Aggregators ---
    src_ips = set()
    dst_ips = set()
    dst_ports = set()
    
    tcp_count = 0
    udp_count = 0
    icmp_count = 0
    
    durations = []
    total_bytes = 0
    total_packets = 0
    outbound_bytes = 0
    inbound_bytes = 0
    outbound_packets = 0
    inbound_packets = 0
    
    failed_connections = 0
    short_connections = 0
    long_connections = 0
    
    # Track destinations and ports per source IP
    dsts_per_source: dict[str, set[str]] = {}
    ports_per_source: dict[str, set[int]] = {}
    
    for flow in flows:
        src_ip = flow.source.ip
        dst_ip = flow.destination.ip
        dst_port = flow.destination.port
        proto = flow.protocol.lower()
        
        src_ips.add(src_ip)
        dst_ips.add(dst_ip)
        dst_ports.add(dst_port)
        
        if proto == "tcp":
            tcp_count += 1
        elif proto == "udp":
            udp_count += 1
        elif proto == "icmp":
            icmp_count += 1
            
        if flow.duration is not None:
            durations.append(flow.duration)
            if flow.duration < 1.0:
                short_connections += 1
            elif flow.duration > 60.0:
                long_connections += 1
                
        # Connection state (failed logic: e.g., REJ, RST, OTH without success)
        # Zeek typical failed states: REJ, RSTOS0, RSTR, S0
        if flow.connection_state in {"REJ", "RSTOS0", "RSTR", "S0"}:
            failed_connections += 1
            
        orig_b = flow.orig_bytes or 0
        resp_b = flow.resp_bytes or 0
        orig_p = flow.orig_packets or 0
        resp_p = flow.resp_packets or 0
        
        outbound_bytes += orig_b
        inbound_bytes += resp_b
        total_bytes += (orig_b + resp_b)
        
        outbound_packets += orig_p
        inbound_packets += resp_p
        total_packets += (orig_p + resp_p)
        
        if src_ip not in dsts_per_source:
            dsts_per_source[src_ip] = set()
        dsts_per_source[src_ip].add(dst_ip)
        
        if src_ip not in ports_per_source:
            ports_per_source[src_ip] = set()
        ports_per_source[src_ip].add(dst_port)

    # --- Calculations ---
    mean_duration = statistics.mean(durations) if durations else None
    median_duration = statistics.median(durations) if durations else None
    max_duration = max(durations) if durations else None
    
    mean_bytes = total_bytes / count
    mean_packets = total_packets / count
    
    bytes_ratio = outbound_bytes / (inbound_bytes + 1.0)
    packets_ratio = outbound_packets / (inbound_packets + 1.0)
    
    failed_ratio = failed_connections / count
    short_ratio = short_connections / count
    long_ratio = long_connections / count
    
    unique_dsts_per_src = sum(len(d) for d in dsts_per_source.values()) / len(src_ips)
    unique_ports_per_src = sum(len(p) for p in ports_per_source.values()) / len(src_ips)
    
    # We leave temporal rates (connection_rate, etc.) to temporal_features.py
    # or calculate here if window is known. The prompt implies rates here? 
    # Prompt: connection_rate, new_destination_rate, new_port_rate.
    # To do that, we need the window. We'll compute temporal features in temporal_features.py
    
    # Assemble FeatureValues
    return [
        FeatureValue(name=FeatureName.FLOW_COUNT.value, value=float(count)),
        FeatureValue(name=FeatureName.FLOW_UNIQUE_SOURCE_IPS.value, value=float(len(src_ips))),
        FeatureValue(name=FeatureName.FLOW_UNIQUE_DESTINATION_IPS.value, value=float(len(dst_ips))),
        FeatureValue(name=FeatureName.FLOW_UNIQUE_DESTINATION_PORTS.value, value=float(len(dst_ports))),
        FeatureValue(name=FeatureName.FLOW_TCP_COUNT.value, value=float(tcp_count)),
        FeatureValue(name=FeatureName.FLOW_UDP_COUNT.value, value=float(udp_count)),
        FeatureValue(name=FeatureName.FLOW_ICMP_COUNT.value, value=float(icmp_count)),
        FeatureValue(name=FeatureName.FLOW_MEAN_DURATION.value, value=mean_duration, present=mean_duration is not None),
        FeatureValue(name=FeatureName.FLOW_MEDIAN_DURATION.value, value=median_duration, present=median_duration is not None),
        FeatureValue(name=FeatureName.FLOW_MAX_DURATION.value, value=max_duration, present=max_duration is not None),
        FeatureValue(name=FeatureName.FLOW_TOTAL_BYTES.value, value=float(total_bytes)),
        FeatureValue(name=FeatureName.FLOW_TOTAL_PACKETS.value, value=float(total_packets)),
        FeatureValue(name=FeatureName.FLOW_MEAN_BYTES_PER_FLOW.value, value=float(mean_bytes)),
        FeatureValue(name=FeatureName.FLOW_MEAN_PACKETS_PER_FLOW.value, value=float(mean_packets)),
        FeatureValue(name=FeatureName.FLOW_OUTBOUND_BYTES.value, value=float(outbound_bytes)),
        FeatureValue(name=FeatureName.FLOW_INBOUND_BYTES.value, value=float(inbound_bytes)),
        FeatureValue(name=FeatureName.FLOW_BYTES_RATIO.value, value=float(bytes_ratio)),
        FeatureValue(name=FeatureName.FLOW_PACKETS_RATIO.value, value=float(packets_ratio)),
        FeatureValue(name=FeatureName.CONN_FAILED_RATIO.value, value=float(failed_ratio)),
        FeatureValue(name=FeatureName.CONN_SHORT_RATIO.value, value=float(short_ratio)),
        FeatureValue(name=FeatureName.CONN_LONG_RATIO.value, value=float(long_ratio)),
        FeatureValue(name=FeatureName.CONN_UNIQUE_DESTINATIONS_PER_SOURCE.value, value=float(unique_dsts_per_src)),
        FeatureValue(name=FeatureName.CONN_UNIQUE_PORTS_PER_SOURCE.value, value=float(unique_ports_per_src)),
    ]


def _build_empty_flow_features() -> list[FeatureValue]:
    return [
        FeatureValue(name=FeatureName.FLOW_COUNT.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_UNIQUE_SOURCE_IPS.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_UNIQUE_DESTINATION_IPS.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_UNIQUE_DESTINATION_PORTS.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_TCP_COUNT.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_UDP_COUNT.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_ICMP_COUNT.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_MEAN_DURATION.value, value=None, present=False),
        FeatureValue(name=FeatureName.FLOW_MEDIAN_DURATION.value, value=None, present=False),
        FeatureValue(name=FeatureName.FLOW_MAX_DURATION.value, value=None, present=False),
        FeatureValue(name=FeatureName.FLOW_TOTAL_BYTES.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_TOTAL_PACKETS.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_MEAN_BYTES_PER_FLOW.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_MEAN_PACKETS_PER_FLOW.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_OUTBOUND_BYTES.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_INBOUND_BYTES.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_BYTES_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.FLOW_PACKETS_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.CONN_FAILED_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.CONN_SHORT_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.CONN_LONG_RATIO.value, value=0.0),
        FeatureValue(name=FeatureName.CONN_UNIQUE_DESTINATIONS_PER_SOURCE.value, value=0.0),
        FeatureValue(name=FeatureName.CONN_UNIQUE_PORTS_PER_SOURCE.value, value=0.0),
    ]
