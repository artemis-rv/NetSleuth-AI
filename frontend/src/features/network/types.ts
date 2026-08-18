/**
 * Network flow domain types — derived from openapi-v1.json schemas:
 * FlowListItem, FlowDetailResponse, FlowListResponse, ProtocolEventResponse.
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
  protocol?: string;
  service?: string;
}
