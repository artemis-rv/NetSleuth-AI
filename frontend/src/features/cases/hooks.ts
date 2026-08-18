import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { caseKeys } from './query-keys';
import { getCases, getCase, createCase, updateCase } from './api';
import type { CasesFilters, CreateCaseRequest, UpdateCaseRequest } from './types';

/**
 * Query hook for the paginated cases list.
 * Keeps server data out of global React context.
 */
export function useCasesQuery(filters: CasesFilters = {}) {
  return useQuery({
    queryKey: caseKeys.list(filters as Record<string, unknown>),
    queryFn: () => getCases(filters),
  });
}

/**
 * Query hook for a single case detail.
 */
export function useCaseQuery(caseId: string) {
  return useQuery({
    queryKey: caseKeys.detail(caseId),
    queryFn: () => getCase(caseId),
    enabled: !!caseId,
  });
}

/**
 * Mutation for creating a new case.
 * Invalidates the cases list cache on success.
 */
export function useCreateCaseMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateCaseRequest) => createCase(payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: caseKeys.lists() });
    },
  });
}

/**
 * Mutation for updating an existing case.
 * Invalidates both the detail and the list cache on success.
 */
export function useUpdateCaseMutation(caseId: string) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: UpdateCaseRequest) => updateCase(caseId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: caseKeys.detail(caseId) });
      queryClient.invalidateQueries({ queryKey: caseKeys.lists() });
    },
  });
}
