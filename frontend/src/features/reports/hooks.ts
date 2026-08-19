import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { reportKeys } from './query-keys';
import { getCaseReports, getReport, generateReport } from './api';
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

export function useGenerateReportMutation(caseId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ format, title }: { format: string; title?: string }) =>
      generateReport(caseId, format, title),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: reportKeys.all });
    },
  });
}

