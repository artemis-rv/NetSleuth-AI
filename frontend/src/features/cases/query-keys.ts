// Centralized query key factory for all case-related queries.
// Used by hooks and mutation invalidations to maintain consistency.

export const caseKeys = {
  all: ['cases'] as const,
  lists: () => [...caseKeys.all, 'list'] as const,
  list: (filters: Record<string, unknown>) => [...caseKeys.lists(), filters] as const,
  details: () => [...caseKeys.all, 'detail'] as const,
  detail: (caseId: string) => [...caseKeys.details(), caseId] as const,
};
