import { apiClient } from '../../api/client';
import type { FindingListResponse, FindingDetailResponse, FindingsFilters } from './types';

/**
 * Fetch paginated findings for a case.
 * Maps to: GET /api/v1/cases/{case_id}/findings
 */
export async function getFindings(
  caseId: string,
  filters: FindingsFilters = {},
): Promise<FindingListResponse> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  if (filters.activity) params.activity = filters.activity;
  if (filters.decision_state) params.decision_state = filters.decision_state;
  if (filters.min_risk !== undefined) params.min_risk = String(filters.min_risk);

  return apiClient<FindingListResponse>(`/api/v1/cases/${caseId}/findings`, { params });
}

/**
 * Fetch a single finding by ID.
 * Maps to: GET /api/v1/findings/{finding_id}
 */
export async function getFinding(findingId: string): Promise<FindingDetailResponse> {
  return apiClient<FindingDetailResponse>(`/api/v1/findings/${findingId}`);
}
