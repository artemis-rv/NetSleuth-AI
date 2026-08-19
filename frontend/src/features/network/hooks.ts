import { useQuery } from '@tanstack/react-query';
import { flowKeys } from './query-keys';
import { getFlows, getFlow, getFlowEvents, getNetworkIPEntities, getEndpointContexts, getEndpointContextDetail } from './api';
import type { FlowsFilters, NetworkEndpointContext } from './types';

export function useNetworkIPEntitiesQuery(caseId: string) {
  return useQuery({
    queryKey: ['network', 'entities', caseId],
    queryFn: () => getNetworkIPEntities(caseId),
    enabled: !!caseId,
  });
}

export function useEndpointContextsQuery(caseId: string, filters: FlowsFilters = {}) {
  return useQuery({
    queryKey: ['network', 'endpoints', caseId, filters],
    queryFn: () => getEndpointContexts(caseId, filters),
    enabled: !!caseId,
  });
}

export function useEndpointDetailQuery(caseId: string, ip: string) {
  return useQuery<NetworkEndpointContext>({
    queryKey: ['network', 'endpointDetail', caseId, ip],
    queryFn: () => getEndpointContextDetail(caseId, ip),
    enabled: !!caseId && !!ip,
  });
}

export function useFlowsQuery(caseId: string, filters: FlowsFilters = {}) {
  return useQuery({
    queryKey: flowKeys.list(caseId, filters as Record<string, unknown>),
    queryFn: () => getFlows(caseId, filters),
    enabled: !!caseId,
  });
}

export function useFlowDetailQuery(flowId: string | null) {
  return useQuery({
    queryKey: flowKeys.detail(flowId ?? ''),
    queryFn: () => getFlow(flowId!),
    enabled: !!flowId,
  });
}

export function useFlowEventsQuery(flowId: string | null) {
  return useQuery({
    queryKey: flowKeys.events(flowId ?? ''),
    queryFn: () => getFlowEvents(flowId!),
    enabled: !!flowId,
  });
}
