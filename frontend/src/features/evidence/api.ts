import { apiClient } from '../../api/client';
import type {
  EvidenceListResponse,
  EvidenceResponse,
  EvidenceVerificationResponse,
  EvidenceItemListResponse,
  EvidenceItemResponse,
  CustodyEventListResponse,
  EvidenceFilters,
} from './types';

/**
 * List evidence for a case.
 * GET /api/v1/cases/{case_id}/evidence
 */
export async function getCaseEvidence(
  caseId: string,
  filters: EvidenceFilters = {},
): Promise<EvidenceListResponse> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  return apiClient<EvidenceListResponse>(`/api/v1/cases/${caseId}/evidence`, { params });
}

/**
 * Get single evidence detail.
 * GET /api/v1/evidence/{evidence_id}
 */
export async function getEvidence(evidenceId: string): Promise<EvidenceResponse> {
  return apiClient<EvidenceResponse>(`/api/v1/evidence/${evidenceId}`);
}

/**
 * Verify evidence integrity.
 * POST /api/v1/evidence/{evidence_id}/verify
 */
export async function verifyEvidence(evidenceId: string): Promise<EvidenceVerificationResponse> {
  return apiClient<EvidenceVerificationResponse>(`/api/v1/evidence/${evidenceId}/verify`, {
    method: 'POST',
  });
}

/**
 * List custody evidence items for a case.
 * GET /api/v1/custody/cases/{case_id}/evidence-items
 */
export async function getCustodyItems(
  caseId: string,
  filters: EvidenceFilters = {},
): Promise<EvidenceItemListResponse> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  return apiClient<EvidenceItemListResponse>(`/api/v1/custody/cases/${caseId}/evidence-items`, { params });
}

/**
 * Get single custody evidence item.
 * GET /api/v1/custody/items/{item_id}
 */
export async function getCustodyItem(itemId: string): Promise<EvidenceItemResponse> {
  return apiClient<EvidenceItemResponse>(`/api/v1/custody/items/${itemId}`);
}

/**
 * List custody events for an item.
 * GET /api/v1/custody/items/{item_id}/events
 */
export async function getCustodyEvents(itemId: string): Promise<CustodyEventListResponse> {
  return apiClient<CustodyEventListResponse>(`/api/v1/custody/items/${itemId}/events`);
}
