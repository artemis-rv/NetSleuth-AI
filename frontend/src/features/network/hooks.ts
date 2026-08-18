import { useQuery } from '@tanstack/react-query';
import { flowKeys } from './query-keys';
import { getFlows, getFlow, getFlowEvents } from './api';
import type { FlowsFilters } from './types';

/**
 * Query hook for the paginated flows list for a case.
 */
export function useFlowsQuery(caseId: string, filters: FlowsFilters = {}) {
  return useQuery({
    queryKey: flowKeys.list(caseId, filters as Record<string, unknown>),
    queryFn: () => getFlows(caseId, filters),
    enabled: !!caseId,
  });
}

/**
 * Query hook for a single flow detail.
 */
export function useFlowDetailQuery(flowId: string | null) {
  return useQuery({
    queryKey: flowKeys.detail(flowId ?? ''),
    queryFn: () => getFlow(flowId!),
    enabled: !!flowId,
  });
}

/**
 * Query hook for protocol events belonging to a flow.
 */
export function useFlowEventsQuery(flowId: string | null) {
  return useQuery({
    queryKey: flowKeys.events(flowId ?? ''),
    queryFn: () => getFlowEvents(flowId!),
    enabled: !!flowId,
  });
}
