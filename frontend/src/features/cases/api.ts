import { apiClient } from '../../api/client';
import type { CaseResponse, CreateCaseRequest, UpdateCaseRequest, PaginatedCases, CasesFilters } from './types';

/**
 * Fetch a paginated list of cases with optional filtering.
 * Maps to: GET /api/v1/cases
 */
export async function getCases(filters: CasesFilters = {}): Promise<PaginatedCases> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  if (filters.status) params.status = filters.status;
  if (filters.priority) params.priority = filters.priority;
  if (filters.sort_by) params.sort_by = filters.sort_by;

  return apiClient<PaginatedCases>('/api/v1/cases', { params });
}

/**
 * Fetch a single case by ID.
 * Maps to: GET /api/v1/cases/{case_id}
 */
export async function getCase(caseId: string): Promise<CaseResponse> {
  return apiClient<CaseResponse>(`/api/v1/cases/${caseId}`);
}

/**
 * Create a new investigation case.
 * Maps to: POST /api/v1/cases
 */
export async function createCase(payload: CreateCaseRequest): Promise<CaseResponse> {
  return apiClient<CaseResponse>('/api/v1/cases', {
    method: 'POST',
    body: JSON.stringify(payload),
  });
}

/**
 * Update specific fields of an existing case.
 * Maps to: PATCH /api/v1/cases/{case_id}
 */
export async function updateCase(caseId: string, payload: UpdateCaseRequest): Promise<CaseResponse> {
  return apiClient<CaseResponse>(`/api/v1/cases/${caseId}`, {
    method: 'PATCH',
    body: JSON.stringify(payload),
  });
}
