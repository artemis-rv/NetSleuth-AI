import { useQuery } from '@tanstack/react-query';
import { getSystemStatus } from './api';

export const adminKeys = {
  all: ['admin'] as const,
  systemStatus: () => [...adminKeys.all, 'system-status'] as const,
};

export function useSystemStatusQuery() {
  return useQuery({
    queryKey: adminKeys.systemStatus(),
    queryFn: getSystemStatus,
  });
}
