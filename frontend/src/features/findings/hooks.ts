import { useQuery } from '@tanstack/react-query';
import { findingKeys } from './query-keys';
import { getFindings, getFinding } from './api';
import type { FindingsFilters } from './types';

/**
 * Query hook for the paginated findings list for a case.
 */
export function useFindingsQuery(caseId: string, filters: FindingsFilters = {}) {
  return useQuery({
    queryKey: findingKeys.list(caseId, filters as Record<string, unknown>),
    queryFn: () => getFindings(caseId, filters),
    enabled: !!caseId,
  });
}

/**
 * Query hook for a single finding detail.
 */
export function useFindingDetailQuery(findingId: string | null) {
  return useQuery({
    queryKey: findingKeys.detail(findingId ?? ''),
    queryFn: () => getFinding(findingId!),
    enabled: !!findingId,
  });
}
