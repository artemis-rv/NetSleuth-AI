export const analysisKeys = {
  all: ['analysis'] as const,
  lists: () => [...analysisKeys.all, 'list'] as const,
  list: (caseId: string, filters?: string) => [...analysisKeys.lists(), { caseId, filters }] as const,
  details: () => [...analysisKeys.all, 'detail'] as const,
  detail: (caseId: string, analysisId: string) => [...analysisKeys.details(), { caseId, analysisId }] as const,
};
