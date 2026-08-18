import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { evidenceKeys } from './query-keys';
import {
  getCaseEvidence,
  getEvidence,
  verifyEvidence,
  getCustodyItems,
  getCustodyEvents,
} from './api';
import type { EvidenceFilters } from './types';

export function useCaseEvidenceQuery(caseId: string, filters: EvidenceFilters = {}) {
  return useQuery({
    queryKey: evidenceKeys.caseEvidence(caseId, filters as Record<string, unknown>),
    queryFn: () => getCaseEvidence(caseId, filters),
    enabled: !!caseId,
  });
}

export function useEvidenceQuery(evidenceId: string | null) {
  return useQuery({
    queryKey: evidenceKeys.detail(evidenceId ?? ''),
    queryFn: () => getEvidence(evidenceId!),
    enabled: !!evidenceId,
  });
}

export function useVerifyEvidenceMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (evidenceId: string) => verifyEvidence(evidenceId),
    onSuccess: (data) => {
      queryClient.invalidateQueries({ queryKey: evidenceKeys.detail(data.evidence_id) });
    },
  });
}

export function useCustodyItemsQuery(caseId: string, filters: EvidenceFilters = {}) {
  return useQuery({
    queryKey: evidenceKeys.custodyItems(caseId, filters as Record<string, unknown>),
    queryFn: () => getCustodyItems(caseId, filters),
    enabled: !!caseId,
  });
}

export function useCustodyEventsQuery(itemId: string | null) {
  return useQuery({
    queryKey: evidenceKeys.custodyEvents(itemId ?? ''),
    queryFn: () => getCustodyEvents(itemId!),
    enabled: !!itemId,
  });
}
