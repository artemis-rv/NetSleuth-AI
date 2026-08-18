/**
 * TanStack Query key factory for the network flows domain.
 */
export const flowKeys = {
  all: ['flows'] as const,
  lists: () => [...flowKeys.all, 'list'] as const,
  list: (caseId: string, filters: Record<string, unknown> = {}) =>
    [...flowKeys.lists(), caseId, filters] as const,
  details: () => [...flowKeys.all, 'detail'] as const,
  detail: (flowId: string) => [...flowKeys.details(), flowId] as const,
  events: (flowId: string) => [...flowKeys.detail(flowId), 'events'] as const,
};
