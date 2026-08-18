import { apiClient } from '../../api/client';
import type { SystemStatusResponse } from './types';

/**
 * Get System Status (Administrator only).
 * GET /api/v1/admin/system-status
 */
export async function getSystemStatus(): Promise<SystemStatusResponse> {
  return apiClient<SystemStatusResponse>('/api/v1/admin/system-status');
}
