/**
 * TanStack Query key factory for the investigation domain.
 */
export const investigationKeys = {
  all: ['investigation'] as const,

  timeline: (caseId: string, filters: Record<string, unknown> = {}) =>
    [...investigationKeys.all, 'timeline', caseId, filters] as const,

  entities: (caseId: string, filters: Record<string, unknown> = {}) =>
    [...investigationKeys.all, 'entities', caseId, filters] as const,

  entity: (entityId: string) =>
    [...investigationKeys.all, 'entity', entityId] as const,

  relationships: (caseId: string, filters: Record<string, unknown> = {}) =>
    [...investigationKeys.all, 'relationships', caseId, filters] as const,

  behaviors: (caseId: string, filters: Record<string, unknown> = {}) =>
    [...investigationKeys.all, 'behaviors', caseId, filters] as const,

  mitre: (caseId: string, filters: Record<string, unknown> = {}) =>
    [...investigationKeys.all, 'mitre', caseId, filters] as const,

  graph: (caseId: string) =>
    [...investigationKeys.all, 'graph', caseId] as const,

  attackChain: (caseId: string) =>
    [...investigationKeys.all, 'attack-chain', caseId] as const,
};
