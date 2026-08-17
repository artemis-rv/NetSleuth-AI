"""
feature_schema.py
-----------------
M2 V1 Canonical Feature Schema.

This module defines every feature name used in M2 as typed constants
(FeatureName enum) and a versioned schema descriptor (FEATURE_SCHEMA).

RULES:
  - All feature names used anywhere in M2 MUST come from this enum.
  - Do not scatter raw string literals for feature names.
  - Features are derived from M1 NetworkIntelligencePackage data only.
  - New features require a schema version bump.

SCHEMA VERSION: 1.0
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Literal

FEATURE_SCHEMA_VERSION = "1.0"


# ---------------------------------------------------------------------------
# FEATURE NAME ENUM
# ---------------------------------------------------------------------------


class FeatureName(str, Enum):
    """Canonical M2 V1 feature name registry.

    Every feature produced by the M2 pipeline must be named using this
    enum.  Do NOT use raw string literals for feature names outside this
    file.

    Groups:
      FLOW_*              — derived from M1 Flow objects
      CONN_*              — connection-behaviour aggregates
      DNS_*               — derived from M1 DNSData ProtocolEvents
      HTTP_*              — derived from M1 HTTPData ProtocolEvents
      TLS_*               — derived from M1 TLSData ProtocolEvents
      TEMPORAL_*          — time-based statistics
      DIST_*              — entropy / distribution statistics
    """

    # --- FLOW ---------------------------------------------------------------
    FLOW_COUNT = "flow_count"
    FLOW_UNIQUE_SOURCE_IPS = "unique_source_ips"
    FLOW_UNIQUE_DESTINATION_IPS = "unique_destination_ips"
    FLOW_UNIQUE_DESTINATION_PORTS = "unique_destination_ports"
    FLOW_TCP_COUNT = "tcp_flow_count"
    FLOW_UDP_COUNT = "udp_flow_count"
    FLOW_ICMP_COUNT = "icmp_flow_count"
    FLOW_MEAN_DURATION = "mean_duration"
    FLOW_MEDIAN_DURATION = "median_duration"
    FLOW_MAX_DURATION = "max_duration"
    FLOW_TOTAL_BYTES = "total_bytes"
    FLOW_TOTAL_PACKETS = "total_packets"
    FLOW_MEAN_BYTES_PER_FLOW = "mean_bytes_per_flow"
    FLOW_MEAN_PACKETS_PER_FLOW = "mean_packets_per_flow"
    FLOW_OUTBOUND_BYTES = "outbound_bytes"
    FLOW_INBOUND_BYTES = "inbound_bytes"
    FLOW_BYTES_RATIO = "bytes_ratio"
    FLOW_PACKETS_RATIO = "packets_ratio"

    # --- CONNECTION BEHAVIOUR -----------------------------------------------
    CONN_FAILED_RATIO = "failed_connection_ratio"
    CONN_SHORT_RATIO = "short_connection_ratio"
    CONN_LONG_RATIO = "long_connection_ratio"
    CONN_UNIQUE_DESTINATIONS_PER_SOURCE = "unique_destinations_per_source"
    CONN_UNIQUE_PORTS_PER_SOURCE = "unique_ports_per_source"
    CONN_CONNECTION_RATE = "connection_rate"
    CONN_NEW_DESTINATION_RATE = "new_destination_rate"
    CONN_NEW_PORT_RATE = "new_port_rate"

    # --- DNS ----------------------------------------------------------------
    DNS_QUERY_COUNT = "dns_query_count"
    DNS_UNIQUE_DOMAINS = "unique_domains"
    DNS_UNIQUE_QUERY_TYPES = "unique_query_types"
    DNS_NXDOMAIN_RATIO = "nxdomain_ratio"
    DNS_ANSWER_COUNT = "dns_answer_count"
    DNS_UNIQUE_ANSWER_IPS = "unique_answer_ips"
    DNS_MEAN_DOMAIN_LENGTH = "mean_domain_length"
    DNS_MAX_DOMAIN_LENGTH = "max_domain_length"
    DNS_MEAN_LABEL_LENGTH = "mean_label_length"
    DNS_MAX_LABEL_LENGTH = "max_label_length"
    DNS_SUBDOMAIN_DEPTH = "subdomain_depth"
    DNS_QUERY_RATE = "dns_query_rate"
    DNS_UNIQUE_DOMAINS_PER_SOURCE = "unique_domains_per_source"

    # --- HTTP ---------------------------------------------------------------
    HTTP_REQUEST_COUNT = "http_request_count"
    HTTP_UNIQUE_HOSTS = "unique_http_hosts"
    HTTP_UNIQUE_URIS = "unique_http_uris"
    HTTP_METHOD_COUNT = "http_method_count"
    HTTP_GET_RATIO = "get_ratio"
    HTTP_POST_RATIO = "post_ratio"
    HTTP_ERROR_STATUS_RATIO = "error_status_ratio"
    HTTP_REDIRECT_RATIO = "redirect_ratio"
    HTTP_DOWNLOAD_BYTES = "download_bytes"
    HTTP_UPLOAD_BYTES = "upload_bytes"
    HTTP_UNIQUE_USER_AGENTS = "unique_user_agents"
    HTTP_MISSING_USER_AGENT_RATIO = "missing_user_agent_ratio"
    HTTP_URI_LENGTH_MEAN = "uri_length_mean"
    HTTP_URI_LENGTH_MAX = "uri_length_max"

    # --- TLS ----------------------------------------------------------------
    TLS_CONNECTION_COUNT = "tls_connection_count"
    TLS_UNIQUE_SNI = "unique_sni"
    TLS_VERSION_DISTRIBUTION = "tls_version_distribution"
    TLS_CIPHER_DISTRIBUTION = "cipher_distribution"
    TLS_MISSING_SNI_RATIO = "missing_sni_ratio"
    TLS_CERT_VALIDITY_DURATION = "certificate_validity_duration"
    TLS_UNIQUE_DESTINATIONS = "unique_tls_destinations"

    # --- TEMPORAL -----------------------------------------------------------
    TEMPORAL_OBSERVATION_DURATION = "observation_duration"
    TEMPORAL_EVENT_RATE = "event_rate"
    TEMPORAL_FLOW_RATE = "flow_rate"
    TEMPORAL_DNS_RATE = "dns_rate"
    TEMPORAL_HTTP_RATE = "http_rate"
    TEMPORAL_TLS_RATE = "tls_rate"
    TEMPORAL_PERIODICITY_SCORE = "periodicity_score"
    TEMPORAL_INTERARRIVAL_MEAN = "interarrival_mean"
    TEMPORAL_INTERARRIVAL_STD = "interarrival_std"
    TEMPORAL_INTERARRIVAL_CV = "interarrival_cv"

    # --- DISTRIBUTION / ENTROPY ---------------------------------------------
    DIST_DESTINATION_ENTROPY = "destination_entropy"
    DIST_PORT_ENTROPY = "port_entropy"
    DIST_DOMAIN_ENTROPY = "domain_entropy"
    DIST_PROTOCOL_ENTROPY = "protocol_entropy"


# ---------------------------------------------------------------------------
# FEATURE DESCRIPTOR
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class FeatureDescriptor:
    """Static metadata about one canonical feature."""

    name: FeatureName
    group: Literal[
        "flow",
        "connection_behaviour",
        "dns",
        "http",
        "tls",
        "temporal",
        "distribution",
    ]
    dtype: Literal["float", "int", "categorical"]
    description: str
    nullable: bool = True  # True when the source data may not contain this feature


# ---------------------------------------------------------------------------
# CANONICAL FEATURE SCHEMA  v1.0
# ---------------------------------------------------------------------------

FEATURE_SCHEMA: dict[FeatureName, FeatureDescriptor] = {
    # FLOW
    FeatureName.FLOW_COUNT: FeatureDescriptor(FeatureName.FLOW_COUNT, "flow", "int", "Total number of flows in the observation window"),
    FeatureName.FLOW_UNIQUE_SOURCE_IPS: FeatureDescriptor(FeatureName.FLOW_UNIQUE_SOURCE_IPS, "flow", "int", "Number of distinct source IP addresses"),
    FeatureName.FLOW_UNIQUE_DESTINATION_IPS: FeatureDescriptor(FeatureName.FLOW_UNIQUE_DESTINATION_IPS, "flow", "int", "Number of distinct destination IP addresses"),
    FeatureName.FLOW_UNIQUE_DESTINATION_PORTS: FeatureDescriptor(FeatureName.FLOW_UNIQUE_DESTINATION_PORTS, "flow", "int", "Number of distinct destination ports"),
    FeatureName.FLOW_TCP_COUNT: FeatureDescriptor(FeatureName.FLOW_TCP_COUNT, "flow", "int", "Number of TCP flows"),
    FeatureName.FLOW_UDP_COUNT: FeatureDescriptor(FeatureName.FLOW_UDP_COUNT, "flow", "int", "Number of UDP flows"),
    FeatureName.FLOW_ICMP_COUNT: FeatureDescriptor(FeatureName.FLOW_ICMP_COUNT, "flow", "int", "Number of ICMP flows"),
    FeatureName.FLOW_MEAN_DURATION: FeatureDescriptor(FeatureName.FLOW_MEAN_DURATION, "flow", "float", "Mean flow duration in seconds", nullable=True),
    FeatureName.FLOW_MEDIAN_DURATION: FeatureDescriptor(FeatureName.FLOW_MEDIAN_DURATION, "flow", "float", "Median flow duration in seconds", nullable=True),
    FeatureName.FLOW_MAX_DURATION: FeatureDescriptor(FeatureName.FLOW_MAX_DURATION, "flow", "float", "Maximum flow duration in seconds", nullable=True),
    FeatureName.FLOW_TOTAL_BYTES: FeatureDescriptor(FeatureName.FLOW_TOTAL_BYTES, "flow", "int", "Total bytes across all flows"),
    FeatureName.FLOW_TOTAL_PACKETS: FeatureDescriptor(FeatureName.FLOW_TOTAL_PACKETS, "flow", "int", "Total packets across all flows"),
    FeatureName.FLOW_MEAN_BYTES_PER_FLOW: FeatureDescriptor(FeatureName.FLOW_MEAN_BYTES_PER_FLOW, "flow", "float", "Mean bytes per flow"),
    FeatureName.FLOW_MEAN_PACKETS_PER_FLOW: FeatureDescriptor(FeatureName.FLOW_MEAN_PACKETS_PER_FLOW, "flow", "float", "Mean packets per flow"),
    FeatureName.FLOW_OUTBOUND_BYTES: FeatureDescriptor(FeatureName.FLOW_OUTBOUND_BYTES, "flow", "int", "Total originator (outbound) bytes"),
    FeatureName.FLOW_INBOUND_BYTES: FeatureDescriptor(FeatureName.FLOW_INBOUND_BYTES, "flow", "int", "Total responder (inbound) bytes"),
    FeatureName.FLOW_BYTES_RATIO: FeatureDescriptor(FeatureName.FLOW_BYTES_RATIO, "flow", "float", "Ratio of outbound to inbound bytes (outbound / (inbound + 1))", nullable=True),
    FeatureName.FLOW_PACKETS_RATIO: FeatureDescriptor(FeatureName.FLOW_PACKETS_RATIO, "flow", "float", "Ratio of originator to responder packets", nullable=True),
    # CONNECTION BEHAVIOUR
    FeatureName.CONN_FAILED_RATIO: FeatureDescriptor(FeatureName.CONN_FAILED_RATIO, "connection_behaviour", "float", "Fraction of flows with failed connection state"),
    FeatureName.CONN_SHORT_RATIO: FeatureDescriptor(FeatureName.CONN_SHORT_RATIO, "connection_behaviour", "float", "Fraction of flows with duration < 1 second"),
    FeatureName.CONN_LONG_RATIO: FeatureDescriptor(FeatureName.CONN_LONG_RATIO, "connection_behaviour", "float", "Fraction of flows with duration > 60 seconds"),
    FeatureName.CONN_UNIQUE_DESTINATIONS_PER_SOURCE: FeatureDescriptor(FeatureName.CONN_UNIQUE_DESTINATIONS_PER_SOURCE, "connection_behaviour", "float", "Mean unique destinations per source IP"),
    FeatureName.CONN_UNIQUE_PORTS_PER_SOURCE: FeatureDescriptor(FeatureName.CONN_UNIQUE_PORTS_PER_SOURCE, "connection_behaviour", "float", "Mean unique destination ports per source IP"),
    FeatureName.CONN_CONNECTION_RATE: FeatureDescriptor(FeatureName.CONN_CONNECTION_RATE, "connection_behaviour", "float", "Flows per second over the observation window"),
    FeatureName.CONN_NEW_DESTINATION_RATE: FeatureDescriptor(FeatureName.CONN_NEW_DESTINATION_RATE, "connection_behaviour", "float", "New unique destinations per second"),
    FeatureName.CONN_NEW_PORT_RATE: FeatureDescriptor(FeatureName.CONN_NEW_PORT_RATE, "connection_behaviour", "float", "New unique ports per second"),
    # DNS
    FeatureName.DNS_QUERY_COUNT: FeatureDescriptor(FeatureName.DNS_QUERY_COUNT, "dns", "int", "Total number of DNS queries observed"),
    FeatureName.DNS_UNIQUE_DOMAINS: FeatureDescriptor(FeatureName.DNS_UNIQUE_DOMAINS, "dns", "int", "Number of distinct domain names queried"),
    FeatureName.DNS_UNIQUE_QUERY_TYPES: FeatureDescriptor(FeatureName.DNS_UNIQUE_QUERY_TYPES, "dns", "int", "Number of distinct DNS query types (A, AAAA, MX, …)"),
    FeatureName.DNS_NXDOMAIN_RATIO: FeatureDescriptor(FeatureName.DNS_NXDOMAIN_RATIO, "dns", "float", "Fraction of DNS queries that returned NXDOMAIN"),
    FeatureName.DNS_ANSWER_COUNT: FeatureDescriptor(FeatureName.DNS_ANSWER_COUNT, "dns", "int", "Total DNS answer records observed"),
    FeatureName.DNS_UNIQUE_ANSWER_IPS: FeatureDescriptor(FeatureName.DNS_UNIQUE_ANSWER_IPS, "dns", "int", "Number of distinct IPs returned in DNS answers"),
    FeatureName.DNS_MEAN_DOMAIN_LENGTH: FeatureDescriptor(FeatureName.DNS_MEAN_DOMAIN_LENGTH, "dns", "float", "Mean character length of queried domains"),
    FeatureName.DNS_MAX_DOMAIN_LENGTH: FeatureDescriptor(FeatureName.DNS_MAX_DOMAIN_LENGTH, "dns", "int", "Maximum character length of queried domains"),
    FeatureName.DNS_MEAN_LABEL_LENGTH: FeatureDescriptor(FeatureName.DNS_MEAN_LABEL_LENGTH, "dns", "float", "Mean character length of domain labels (between dots)"),
    FeatureName.DNS_MAX_LABEL_LENGTH: FeatureDescriptor(FeatureName.DNS_MAX_LABEL_LENGTH, "dns", "int", "Maximum character length of any single domain label"),
    FeatureName.DNS_SUBDOMAIN_DEPTH: FeatureDescriptor(FeatureName.DNS_SUBDOMAIN_DEPTH, "dns", "float", "Mean number of subdomain levels (dot count - 1)"),
    FeatureName.DNS_QUERY_RATE: FeatureDescriptor(FeatureName.DNS_QUERY_RATE, "dns", "float", "DNS queries per second"),
    FeatureName.DNS_UNIQUE_DOMAINS_PER_SOURCE: FeatureDescriptor(FeatureName.DNS_UNIQUE_DOMAINS_PER_SOURCE, "dns", "float", "Mean unique domains queried per source IP"),
    # HTTP
    FeatureName.HTTP_REQUEST_COUNT: FeatureDescriptor(FeatureName.HTTP_REQUEST_COUNT, "http", "int", "Total HTTP requests observed"),
    FeatureName.HTTP_UNIQUE_HOSTS: FeatureDescriptor(FeatureName.HTTP_UNIQUE_HOSTS, "http", "int", "Number of distinct HTTP Host header values"),
    FeatureName.HTTP_UNIQUE_URIS: FeatureDescriptor(FeatureName.HTTP_UNIQUE_URIS, "http", "int", "Number of distinct request URIs"),
    FeatureName.HTTP_METHOD_COUNT: FeatureDescriptor(FeatureName.HTTP_METHOD_COUNT, "http", "int", "Number of distinct HTTP methods observed"),
    FeatureName.HTTP_GET_RATIO: FeatureDescriptor(FeatureName.HTTP_GET_RATIO, "http", "float", "Fraction of requests using GET method"),
    FeatureName.HTTP_POST_RATIO: FeatureDescriptor(FeatureName.HTTP_POST_RATIO, "http", "float", "Fraction of requests using POST method"),
    FeatureName.HTTP_ERROR_STATUS_RATIO: FeatureDescriptor(FeatureName.HTTP_ERROR_STATUS_RATIO, "http", "float", "Fraction of responses with 4xx or 5xx status codes"),
    FeatureName.HTTP_REDIRECT_RATIO: FeatureDescriptor(FeatureName.HTTP_REDIRECT_RATIO, "http", "float", "Fraction of responses with 3xx status codes"),
    FeatureName.HTTP_DOWNLOAD_BYTES: FeatureDescriptor(FeatureName.HTTP_DOWNLOAD_BYTES, "http", "int", "Total response body bytes (downloads)"),
    FeatureName.HTTP_UPLOAD_BYTES: FeatureDescriptor(FeatureName.HTTP_UPLOAD_BYTES, "http", "int", "Total request body bytes (uploads)"),
    FeatureName.HTTP_UNIQUE_USER_AGENTS: FeatureDescriptor(FeatureName.HTTP_UNIQUE_USER_AGENTS, "http", "int", "Number of distinct User-Agent strings observed"),
    FeatureName.HTTP_MISSING_USER_AGENT_RATIO: FeatureDescriptor(FeatureName.HTTP_MISSING_USER_AGENT_RATIO, "http", "float", "Fraction of requests with missing or empty User-Agent"),
    FeatureName.HTTP_URI_LENGTH_MEAN: FeatureDescriptor(FeatureName.HTTP_URI_LENGTH_MEAN, "http", "float", "Mean URI character length"),
    FeatureName.HTTP_URI_LENGTH_MAX: FeatureDescriptor(FeatureName.HTTP_URI_LENGTH_MAX, "http", "int", "Maximum URI character length"),
    # TLS
    FeatureName.TLS_CONNECTION_COUNT: FeatureDescriptor(FeatureName.TLS_CONNECTION_COUNT, "tls", "int", "Total TLS connections observed"),
    FeatureName.TLS_UNIQUE_SNI: FeatureDescriptor(FeatureName.TLS_UNIQUE_SNI, "tls", "int", "Number of distinct SNI values"),
    FeatureName.TLS_VERSION_DISTRIBUTION: FeatureDescriptor(FeatureName.TLS_VERSION_DISTRIBUTION, "tls", "categorical", "Distribution of TLS versions as JSON string"),
    FeatureName.TLS_CIPHER_DISTRIBUTION: FeatureDescriptor(FeatureName.TLS_CIPHER_DISTRIBUTION, "tls", "categorical", "Distribution of cipher suites as JSON string"),
    FeatureName.TLS_MISSING_SNI_RATIO: FeatureDescriptor(FeatureName.TLS_MISSING_SNI_RATIO, "tls", "float", "Fraction of TLS connections with no SNI"),
    FeatureName.TLS_CERT_VALIDITY_DURATION: FeatureDescriptor(FeatureName.TLS_CERT_VALIDITY_DURATION, "tls", "float", "Mean certificate validity duration in days", nullable=True),
    FeatureName.TLS_UNIQUE_DESTINATIONS: FeatureDescriptor(FeatureName.TLS_UNIQUE_DESTINATIONS, "tls", "int", "Number of distinct TLS destination IPs"),
    # TEMPORAL
    FeatureName.TEMPORAL_OBSERVATION_DURATION: FeatureDescriptor(FeatureName.TEMPORAL_OBSERVATION_DURATION, "temporal", "float", "Total observation window duration in seconds"),
    FeatureName.TEMPORAL_EVENT_RATE: FeatureDescriptor(FeatureName.TEMPORAL_EVENT_RATE, "temporal", "float", "Protocol events per second"),
    FeatureName.TEMPORAL_FLOW_RATE: FeatureDescriptor(FeatureName.TEMPORAL_FLOW_RATE, "temporal", "float", "Flows per second"),
    FeatureName.TEMPORAL_DNS_RATE: FeatureDescriptor(FeatureName.TEMPORAL_DNS_RATE, "temporal", "float", "DNS queries per second"),
    FeatureName.TEMPORAL_HTTP_RATE: FeatureDescriptor(FeatureName.TEMPORAL_HTTP_RATE, "temporal", "float", "HTTP requests per second"),
    FeatureName.TEMPORAL_TLS_RATE: FeatureDescriptor(FeatureName.TEMPORAL_TLS_RATE, "temporal", "float", "TLS connections per second"),
    FeatureName.TEMPORAL_PERIODICITY_SCORE: FeatureDescriptor(FeatureName.TEMPORAL_PERIODICITY_SCORE, "temporal", "float", "Regularity score of inter-arrival times [0.0, 1.0]; higher = more periodic", nullable=True),
    FeatureName.TEMPORAL_INTERARRIVAL_MEAN: FeatureDescriptor(FeatureName.TEMPORAL_INTERARRIVAL_MEAN, "temporal", "float", "Mean inter-arrival time of flows in seconds", nullable=True),
    FeatureName.TEMPORAL_INTERARRIVAL_STD: FeatureDescriptor(FeatureName.TEMPORAL_INTERARRIVAL_STD, "temporal", "float", "Standard deviation of flow inter-arrival times", nullable=True),
    FeatureName.TEMPORAL_INTERARRIVAL_CV: FeatureDescriptor(FeatureName.TEMPORAL_INTERARRIVAL_CV, "temporal", "float", "Coefficient of variation of inter-arrival times (std/mean)", nullable=True),
    # DISTRIBUTION / ENTROPY
    FeatureName.DIST_DESTINATION_ENTROPY: FeatureDescriptor(FeatureName.DIST_DESTINATION_ENTROPY, "distribution", "float", "Shannon entropy of destination IP distribution"),
    FeatureName.DIST_PORT_ENTROPY: FeatureDescriptor(FeatureName.DIST_PORT_ENTROPY, "distribution", "float", "Shannon entropy of destination port distribution"),
    FeatureName.DIST_DOMAIN_ENTROPY: FeatureDescriptor(FeatureName.DIST_DOMAIN_ENTROPY, "distribution", "float", "Shannon entropy of queried domain distribution"),
    FeatureName.DIST_PROTOCOL_ENTROPY: FeatureDescriptor(FeatureName.DIST_PROTOCOL_ENTROPY, "distribution", "float", "Shannon entropy of protocol distribution"),
}


def schema_feature_names() -> list[str]:
    """Return canonical feature names in deterministic schema order."""
    return [fn.value for fn in FeatureName]


def schema_version() -> str:
    return FEATURE_SCHEMA_VERSION
