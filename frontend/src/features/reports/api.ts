import { apiClient } from '../../api/client';
import { tokenStore } from '../../auth/auth-store';
import type { ReportListResponse, ReportResponse, ReportFilters } from './types';

const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';

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
 * Get single report detail.
 * GET /api/v1/reports/{report_id}
 */
export async function getReport(reportId: string): Promise<ReportResponse> {
  return apiClient<ReportResponse>(`/api/v1/reports/${reportId}`);
}

export function getExportReportUrl(reportId: string, format: 'json' | 'pdf' | 'txt' = 'json'): string {
  return `${BASE_URL}/api/v1/reports/${reportId}/export?format=${format}`;
}

export async function downloadReport(reportId: string, format: 'json' | 'pdf' | 'txt' = 'json', title?: string): Promise<void> {
  const token = tokenStore.get();
  const url = `${BASE_URL}/api/v1/reports/${reportId}/export?format=${format}`;
  
  const response = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });

  if (!response.ok) {
    throw new Error(`Failed to download report (${response.status} ${response.statusText})`);
  }

  const arrayBuffer = await response.arrayBuffer();
  const mimeTypes: Record<string, string> = {
    pdf: 'application/pdf',
    json: 'application/json',
    txt: 'text/plain',
  };
  
  const blob = new Blob([arrayBuffer], { type: mimeTypes[format] || 'application/octet-stream' });
  const downloadUrl = window.URL.createObjectURL(blob);
  
  const safeTitle = (title || 'investigation_report').replace(/[^a-zA-Z0-9_-]/g, '_');
  const filename = `${safeTitle}.${format}`;
  
  const a = document.createElement('a');
  a.href = downloadUrl;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  
  setTimeout(() => {
    window.URL.revokeObjectURL(downloadUrl);
  }, 1000);
}
