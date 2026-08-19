import { apiClient } from '../../api/client';
import type {
  FlowListResponse,
  FlowDetailResponse,
  ProtocolEventListResponse,
  FlowsFilters,
} from './types';

/**
 * Fetch paginated network flows for a case.
 * Maps to: GET /api/v1/cases/{case_id}/flows
 */
export async function getFlows(
  caseId: string,
  filters: FlowsFilters = {},
): Promise<FlowListResponse> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  if (filters.src_ip) params.src_ip = filters.src_ip;
  if (filters.dst_ip) params.dst_ip = filters.dst_ip;
  if (filters.protocol) params.protocol = filters.protocol;
  if (filters.service) params.service = filters.service;

  return apiClient<FlowListResponse>(`/api/v1/cases/${caseId}/flows`, { params });
}

/**
 * Fetch a single flow detail.
 * Maps to: GET /api/v1/flows/{flow_id}
 */
export async function getFlow(flowId: string): Promise<FlowDetailResponse> {
  return apiClient<FlowDetailResponse>(`/api/v1/flows/${flowId}`);
}

/**
 * Fetch protocol events for a flow.
 * Maps to: GET /api/v1/flows/{flow_id}/events
 */
export async function getFlowEvents(flowId: string): Promise<ProtocolEventListResponse> {
  return apiClient<ProtocolEventListResponse>(`/api/v1/flows/${flowId}/events`);
}

/**
 * Fetch contextual network IP entities for a case.
 * Maps to: GET /api/v1/cases/{case_id}/network/entities
 */
export async function getNetworkIPEntities(caseId: string): Promise<import('./types').IPEntityListResponse> {
  return apiClient<import('./types').IPEntityListResponse>(`/api/v1/cases/${caseId}/network/entities`);
}
