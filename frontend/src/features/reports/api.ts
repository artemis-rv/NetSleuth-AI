import { apiClient } from '../../api/client';
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
 * Get single report detail.
 * GET /api/v1/reports/{report_id}
 */
export async function getReport(reportId: string): Promise<ReportResponse> {
  return apiClient<ReportResponse>(`/api/v1/reports/${reportId}`);
}
