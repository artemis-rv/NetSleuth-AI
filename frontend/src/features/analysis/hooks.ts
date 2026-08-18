import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { startAnalysis, getAnalysisJobs } from './api';
import { analysisKeys } from './query-keys';

export function useAnalysisJobs(caseId: string, page = 1) {
  return useQuery({
    queryKey: analysisKeys.list(caseId, `page=${page}`),
    queryFn: () => getAnalysisJobs(caseId, page),
    enabled: !!caseId,
    // Poll every 3 seconds if any job is currently in 'queued' or 'running' state
    refetchInterval: (query) => {
      const data = query.state.data;
      if (!data) return false;
      const hasActiveJob = data.items.some(
        (job) => job.status === 'queued' || job.status === 'running'
      );
      return hasActiveJob ? 3000 : false;
    },
  });
}

export function useStartAnalysis(caseId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (acquisitionId: string) => startAnalysis(caseId, acquisitionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: analysisKeys.lists() });
    },
  });
}
