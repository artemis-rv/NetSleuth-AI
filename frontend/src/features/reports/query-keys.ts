export const reportKeys = {
  all: ['reports'] as const,
  caseReports: (caseId: string, filters: Record<string, unknown> = {}) =>
    [...reportKeys.all, 'case', caseId, filters] as const,
  detail: (reportId: string) =>
    [...reportKeys.all, 'detail', reportId] as const,
};
