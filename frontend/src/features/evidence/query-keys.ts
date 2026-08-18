/**
 * TanStack Query key factory for evidence and custody domain.
 */
export const evidenceKeys = {
  all: ['evidence'] as const,
  caseEvidence: (caseId: string, filters: Record<string, unknown> = {}) =>
    [...evidenceKeys.all, 'case', caseId, filters] as const,
  detail: (evidenceId: string) =>
    [...evidenceKeys.all, 'detail', evidenceId] as const,
  custodyItems: (caseId: string, filters: Record<string, unknown> = {}) =>
    ['custody', 'items', caseId, filters] as const,
  custodyItem: (itemId: string) =>
    ['custody', 'item', itemId] as const,
  custodyEvents: (itemId: string) =>
    ['custody', 'events', itemId] as const,
};
