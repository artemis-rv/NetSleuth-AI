import { useQuery } from '@tanstack/react-query';
import { reportKeys } from './query-keys';
import { getCaseReports, getReport } from './api';
import type { ReportFilters } from './types';

export function useCaseReportsQuery(caseId: string, filters: ReportFilters = {}) {
  return useQuery({
    queryKey: reportKeys.caseReports(caseId, filters as Record<string, unknown>),
    queryFn: () => getCaseReports(caseId, filters),
    enabled: !!caseId,
  });
}

export function useReportQuery(reportId: string | null) {
  return useQuery({
    queryKey: reportKeys.detail(reportId ?? ''),
    queryFn: () => getReport(reportId!),
    enabled: !!reportId,
  });
}
