export const acquisitionKeys = {
  all: ['acquisitions'] as const,
  lists: () => [...acquisitionKeys.all, 'list'] as const,
  list: (caseId: string, filters: string) => [...acquisitionKeys.lists(), { caseId, filters }] as const,
  details: () => [...acquisitionKeys.all, 'detail'] as const,
  detail: (id: string) => [...acquisitionKeys.details(), id] as const,
};

export const evidenceKeys = {
  all: ['evidence'] as const,
  lists: () => [...evidenceKeys.all, 'list'] as const,
  list: (caseId: string, filters: string) => [...evidenceKeys.lists(), { caseId, filters }] as const,
  details: () => [...evidenceKeys.all, 'detail'] as const,
  detail: (id: string) => [...evidenceKeys.details(), id] as const,
};
