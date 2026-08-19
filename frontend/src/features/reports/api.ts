import { apiClient } from '../../api/client';
import { tokenStore } from '../../auth/auth-store';
import type { ReportListResponse, ReportResponse, ReportFilters } from './types';

/**
 * List reports for a case.
 * GET /api/v1/reports/cases/{case_id}/reports
 */
export async function getCaseReports(
  caseId: string,
  filters: ReportFilters = {},
): Promise<ReportListResponse> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  return apiClient<ReportListResponse>(`/api/v1/reports/cases/${caseId}/reports`, { params });
}

/**
 * Generate a new forensic report (PDF, HTML, JSON).
 * POST /api/v1/reports/cases/{case_id}/reports/generate
 */
export async function generateReport(caseId: string, format: string = 'pdf', title?: string): Promise<ReportResponse> {
  return apiClient<ReportResponse>(`/api/v1/reports/cases/${caseId}/reports/generate`, {
    method: 'POST',
    body: JSON.stringify({ format, title }),
  });
}

/**
 * Get single report detail.
 * GET /api/v1/reports/{report_id}
 */
export async function getReport(reportId: string): Promise<ReportResponse> {
  return apiClient<ReportResponse>(`/api/v1/reports/${reportId}`);
}

/**
 * Export and download report artifact file directly in requested format (PDF, JSON, TXT).
 * GET /api/v1/reports/{report_id}/export?format={format}
 */
export async function exportReportBlob(
  reportId: string,
  format: 'json' | 'pdf' | 'txt' | 'html' = 'pdf',
  defaultFilename?: string
): Promise<void> {
  const token = tokenStore.get();
  const headers: Record<string, string> = {};
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  
  const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
  const response = await fetch(`${BASE_URL}/api/v1/reports/${reportId}/export?format=${format}`, {
    headers,
  });
  
  if (!response.ok) {
    if (response.status === 403) {
      throw new Error("You do not have permission to export this report.");
    }
    if (response.status === 404) {
      throw new Error("Report artifact was not found.");
    }
    if (response.status >= 500) {
      throw new Error("Report service is temporarily unavailable.");
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
  
  let filename = defaultFilename || `report_${reportId.slice(0, 8)}.${format}`;
  const disposition = response.headers.get('Content-Disposition');
  if (disposition && disposition.includes('filename=')) {
    const match = disposition.match(/filename="?([^"]+)"?/);
    if (match && match[1]) {
      filename = match[1];
    }
  }
  
  const blob = await response.blob();
  const mimeType = format === 'pdf' ? 'application/pdf' : (format === 'json' ? 'application/json' : 'text/plain');
  const typedBlob = new Blob([blob], { type: mimeType });
  const url = window.URL.createObjectURL(typedBlob);
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

/**
 * Backward compatibility alias for downloadReport
 */
export const downloadReport = exportReportBlob;


