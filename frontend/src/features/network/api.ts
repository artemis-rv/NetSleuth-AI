import { apiClient } from '../../api/client';
import type {
  FlowListResponse,
  FlowDetailResponse,
  ProtocolEventListResponse,
  FlowsFilters,
  NetworkEndpointContextListResponse,
  NetworkEndpointContext,
} from './types';

export async function getFlows(
  caseId: string,
  filters: FlowsFilters = {},
): Promise<FlowListResponse> {
  const params: Record<string, string> = {};
  if (filters.page) params.page = String(filters.page);
  if (filters.page_size) params.page_size = String(filters.page_size);
  if (filters.src_ip && filters.src_ip.trim()) params.src_ip = filters.src_ip.trim();
  if (filters.dst_ip && filters.dst_ip.trim()) params.dst_ip = filters.dst_ip.trim();
  if (filters.protocol && filters.protocol.trim()) params.protocol = filters.protocol.trim();
  if (filters.service && filters.service.trim()) params.service = filters.service.trim();

  return apiClient<FlowListResponse>(`/api/v1/cases/${caseId}/flows`, { params });
}

export async function getFlow(flowId: string): Promise<FlowDetailResponse> {
  return apiClient<FlowDetailResponse>(`/api/v1/flows/${flowId}`);
}

export async function getFlowEvents(flowId: string): Promise<ProtocolEventListResponse> {
  return apiClient<ProtocolEventListResponse>(`/api/v1/flows/${flowId}/events`);
}

export async function getNetworkIPEntities(caseId: string): Promise<import('./types').IPEntityListResponse> {
  return apiClient<import('./types').IPEntityListResponse>(`/api/v1/cases/${caseId}/network/entities`);
}

export async function getEndpointContexts(
  caseId: string,
  filters: FlowsFilters = {},
): Promise<NetworkEndpointContextListResponse> {
  const params: Record<string, string> = {};
  if (filters.page) params.page = String(filters.page);
  if (filters.page_size) params.page_size = String(filters.page_size);
  if (filters.search_ip && filters.search_ip.trim()) params.search_ip = filters.search_ip.trim();
  if (filters.protocol && filters.protocol.trim()) params.protocol = filters.protocol.trim();
  if (filters.service && filters.service.trim()) params.service = filters.service.trim();
  if (filters.port !== undefined && filters.port !== null && String(filters.port).trim() !== '') {
    params.port = String(filters.port).trim();
  }
  if (filters.network_scope && filters.network_scope.trim()) params.network_scope = filters.network_scope.trim();
  if (filters.severity && filters.severity.trim()) params.severity = filters.severity.trim();
  if (filters.min_risk !== undefined && filters.min_risk !== null && String(filters.min_risk).trim() !== '') {
    params.min_risk = String(filters.min_risk).trim();
  }
  if (filters.min_anomaly !== undefined && filters.min_anomaly !== null && String(filters.min_anomaly).trim() !== '') {
    params.min_anomaly = String(filters.min_anomaly).trim();
  }
  if (filters.sort_by && filters.sort_by.trim()) params.sort_by = filters.sort_by.trim();

  return apiClient<NetworkEndpointContextListResponse>(`/api/v1/cases/${caseId}/network/endpoints`, { params });
}

export async function getEndpointContextDetail(
  caseId: string,
  ip: string,
): Promise<NetworkEndpointContext> {
  return apiClient<NetworkEndpointContext>(`/api/v1/cases/${caseId}/network/endpoints/${encodeURIComponent(ip)}`);
}
