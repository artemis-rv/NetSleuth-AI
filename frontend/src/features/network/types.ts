/**
 * Network flow & endpoint forensic context domain types.
 */

export interface FlowListItem {
  flow_id: string;
  timestamp: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  service: string;
  duration: number | null;
  orig_bytes: number | null;
  resp_bytes: number | null;
  connection_state: string | null;
}

export interface FlowDetailResponse extends FlowListItem {
  acquisition_id: string;
  zeek_uid: string;
  start_time: string | null;
  end_time: string | null;
  orig_packets: number | null;
  resp_packets: number | null;
  pcap_frame_start: number | null;
  pcap_frame_end: number | null;
  pcap_byte_offset: number | null;
  pcap_timestamp_start: string | null;
  pcap_timestamp_end: string | null;
  provenance: Record<string, unknown> | null;
}

export interface FlowListResponse {
  items: FlowListItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface ProtocolEventResponse {
  event_id: string;
  flow_id: string;
  zeek_uid: string;
  protocol: string;
  timestamp: string;
  protocol_data: Record<string, unknown>;
  provenance: Record<string, unknown> | null;
}

export interface ProtocolEventListResponse {
  items: ProtocolEventResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface FlowsFilters {
  page?: number;
  page_size?: number;
  src_ip?: string;
  dst_ip?: string;
  search_ip?: string;
  protocol?: string;
  service?: string;
  port?: number;
  network_scope?: string;
  severity?: string;
  min_risk?: number;
  min_anomaly?: number;
  sort_by?: string;
}

export interface IPEntityResponse {
  ip: string;
  classification: string;
  role: string;
  related_domains: string[];
  services: string[];
  first_seen: string | null;
  last_seen: string | null;
  flow_count: number;
  event_count: number;
  finding_count: number;
  flow_ids: string[];
  event_ids: string[];
  artifact_ids: string[];
  finding_ids: string[];
}

export interface IPEntityListResponse {
  items: IPEntityResponse[];
  total: number;
  internal_count: number;
  external_count: number;
}

// Dynamic Network Endpoint Forensic Context Types
export interface CommunicationProfile {
  total_flows: number;
  unique_sources: string[];
  unique_destinations: string[];
  protocols: string[];
  services: string[];
  destination_ports: number[];
  source_ports: number[];
  connection_states: string[];
  total_active_duration: number;
}

export interface TrafficProfile {
  bytes_sent: number;
  bytes_received: number;
  packets_sent: number;
  packets_received: number;
  total_bytes: number;
  total_packets: number;
  avg_flow_duration: number;
}

export interface DNSProtocolProfile {
  query_count: number;
  unique_queries: string[];
  answers_count: number;
  response_codes: string[];
}

export interface HTTPProtocolProfile {
  request_count: number;
  methods: string[];
  hosts: string[];
  uris: string[];
  status_codes: number[];
  user_agents: string[];
}

export interface TLSProtocolProfile {
  session_count: number;
  versions: string[];
  ciphers: string[];
  server_names: string[];
}

export interface ProtocolProfile {
  dns: DNSProtocolProfile;
  http: HTTPProtocolProfile;
  tls: TLSProtocolProfile;
}

export interface ArtifactSummaryItem {
  artifact_id: string;
  type: string;
  value: string;
  source_event_id?: string | null;
  flow_id?: string | null;
  acquisition_id?: string | null;
  evidence_id?: string | null;
}

export interface SeverityBreakdown {
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface M2FindingSummaryItem {
  finding_id: string;
  activity: string;
  severity: string;
  risk_score: number;
  confidence: number;
  anomaly_score?: number | null;
  decision_state: string;
  rationale: string;
}

export interface M2FindingsSummary {
  finding_count: number;
  highest_severity?: string | null;
  max_risk_score: number;
  max_anomaly_score: number;
  avg_confidence: number;
  activity_classes: string[];
  severity_breakdown: SeverityBreakdown;
  items: M2FindingSummaryItem[];
}

export interface TemporalSummary {
  first_seen?: string | null;
  last_seen?: string | null;
  active_duration_seconds: number;
  connection_rate_per_min: number;
}

export interface EvidenceTraceabilityItem {
  flow_id: string;
  zeek_uid: string;
  acquisition_id: string;
  pcap_frame_start?: number | null;
  pcap_frame_end?: number | null;
  pcap_byte_offset?: number | null;
  pcap_timestamp_start?: string | null;
  pcap_timestamp_end?: string | null;
  has_packet_reference: boolean;
}

export interface EvidenceSummary {
  flow_count: number;
  protocol_event_count: number;
  artifact_count: number;
  has_packet_references: boolean;
  traceability_items: EvidenceTraceabilityItem[];
}

export interface NetworkEndpointContext {
  ip: string;
  ip_version: number;
  role: string;
  network_scope: string;
  hostname?: string | null;
  associated_domain?: string | null;
  resolved_dns_names: string[];
  communication: CommunicationProfile;
  traffic: TrafficProfile;
  protocol_activity: ProtocolProfile;
  artifacts: ArtifactSummaryItem[];
  m2_findings: M2FindingsSummary;
  temporal: TemporalSummary;
  evidence: EvidenceSummary;
  flow_ids: string[];
  event_ids: string[];
}

export interface NetworkEndpointContextListResponse {
  items: NetworkEndpointContext[];
  total: number;
  page: number;
  page_size: number;
  internal_count: number;
  external_count: number;
}
