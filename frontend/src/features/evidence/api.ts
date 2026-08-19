import { apiClient } from '../../api/client';
import { tokenStore } from '../../auth/auth-store';
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

/**
 * Export and download raw evidence file directly.
 * GET /api/v1/evidence/{evidence_id}/export
 */
export async function exportEvidenceBlob(
  evidenceId: string,
  defaultFilename: string
): Promise<void> {
  const token = tokenStore.get();
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8001';
  const response = await fetch(`${BASE_URL}/api/v1/evidence/${evidenceId}/export`, {
    headers,
  });
  
  if (!response.ok) {
    if (response.status === 403) {
      throw new Error("You do not have permission to export this evidence. Requires administrator or custodian role.");
    }
    if (response.status === 404) {
      throw new Error("Evidence file was not found.");
    }
    if (response.status >= 500) {
      throw new Error("Evidence service is temporarily unavailable.");
    }
    let errMsg = `Export failed (${response.status})`;
    try {
      const errJson = await response.json();
      if (errJson?.error?.message) {
        errMsg = errJson.error.message;
      }
    } catch {}
    throw new Error(errMsg);
  }
  
  let filename = defaultFilename;
  const disposition = response.headers.get('Content-Disposition');
  if (disposition && disposition.includes('filename=')) {
    const match = disposition.match(/filename="?([^"]+)"?/);
    if (match && match[1]) {
      filename = match[1];
    }
  }
  
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    window.URL.revokeObjectURL(url);
    if (document.body.contains(a)) {
      document.body.removeChild(a);
    }
  }, 1000);
}
