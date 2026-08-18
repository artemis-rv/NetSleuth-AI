/**
 * TanStack Query key factory for the findings domain.
 * Follows the same pattern as caseKeys in features/cases/query-keys.ts.
 */
export const findingKeys = {
  all: ['findings'] as const,
  lists: () => [...findingKeys.all, 'list'] as const,
  list: (caseId: string, filters: Record<string, unknown> = {}) =>
    [...findingKeys.lists(), caseId, filters] as const,
  details: () => [...findingKeys.all, 'detail'] as const,
  detail: (findingId: string) => [...findingKeys.details(), findingId] as const,
};
