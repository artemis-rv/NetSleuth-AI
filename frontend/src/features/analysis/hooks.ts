import { useEffect, useRef } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { startAnalysis, getAnalysisJobs } from './api';
import { analysisKeys } from './query-keys';

export function useAnalysisJobs(caseId: string, page = 1) {
  const queryClient = useQueryClient();
  const prevHasActiveJobRef = useRef<boolean>(false);

  const query = useQuery({
    queryKey: analysisKeys.list(caseId, `page=${page}`),
    queryFn: () => getAnalysisJobs(caseId, page),
    enabled: !!caseId,
    // Poll every 3 seconds if any job is currently in 'queued' or 'running' state
    refetchInterval: (queryState) => {
      const data = queryState.state.data;
      if (!data) return false;
      const hasActiveJob = data?.jobs?.some(
        (job) => job.status === 'queued' || job.status === 'running'
      );
      return hasActiveJob ? 3000 : false;
    },
  });

  const jobs = query.data?.jobs;
  const hasActiveJob = jobs?.some((j) => j.status === 'queued' || j.status === 'running');
  const hasCompletedJob = jobs?.some((j) => j.status === 'completed');

  useEffect(() => {
    // When an active job finishes running and becomes completed, invalidate all dependent case queries
    if (prevHasActiveJobRef.current && !hasActiveJob && hasCompletedJob) {
      queryClient.invalidateQueries({ queryKey: ['cases', caseId] });
      queryClient.invalidateQueries({ queryKey: ['findings', caseId] });
      queryClient.invalidateQueries({ queryKey: ['network', caseId] });
      queryClient.invalidateQueries({ queryKey: ['timeline', caseId] });
      queryClient.invalidateQueries({ queryKey: ['graph', caseId] });
      queryClient.invalidateQueries({ queryKey: ['mitre', caseId] });
      queryClient.invalidateQueries({ queryKey: ['reports', caseId] });
      queryClient.invalidateQueries({ queryKey: ['investigation', caseId] });
    }
    prevHasActiveJobRef.current = !!hasActiveJob;
  }, [hasActiveJob, hasCompletedJob, caseId, queryClient]);

  return query;
}

export function useStartAnalysis(caseId: string) {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: (acquisitionId: string) => startAnalysis(caseId, acquisitionId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: analysisKeys.lists() });
      queryClient.invalidateQueries({ queryKey: ['cases', caseId] });
    },
  });
}
