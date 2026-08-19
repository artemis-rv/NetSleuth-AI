import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { getAcquisitions, getEvidenceList, uploadAcquisition, verifyEvidence } from './api';
import { acquisitionKeys, evidenceKeys } from './query-keys';

export function useAcquisitions(caseId: string, page = 1) {
  return useQuery({
    queryKey: acquisitionKeys.list(caseId, `page=${page}`),
    queryFn: () => getAcquisitions(caseId, page),
    enabled: !!caseId,
  });
}

export function useEvidence(caseId: string, page = 1) {
  return useQuery({
    queryKey: evidenceKeys.list(caseId, `page=${page}`),
    queryFn: () => getEvidenceList(caseId, page),
    enabled: !!caseId,
  });
}

export function useUploadAcquisition(caseId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (files: File[]) => uploadAcquisition(caseId, files),
    onSuccess: () => {
      // Invalidate both lists to fetch the latest state
      queryClient.invalidateQueries({ queryKey: acquisitionKeys.lists() });
      queryClient.invalidateQueries({ queryKey: evidenceKeys.lists() });
    },
  });
}

export function useVerifyEvidence() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (evidenceId: string) => verifyEvidence(evidenceId),
    onSuccess: (_, variables) => {
      // Refetch the evidence lists to update UI
      queryClient.invalidateQueries({ queryKey: evidenceKeys.lists() });
      // Invalidate the specific detail if we end up adding evidence details
      queryClient.invalidateQueries({ queryKey: evidenceKeys.detail(variables) });
    },
  });
}
