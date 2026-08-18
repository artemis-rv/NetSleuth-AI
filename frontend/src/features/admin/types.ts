/**
 * Admin domain types — derived from openapi-v1.json GET /api/v1/admin/system-status
 */

export interface SystemStatusResponse {
  status?: string;
  environment?: string;
  version?: string;
  services?: Record<string, string | boolean>;
  metrics?: Record<string, number | string>;
  [key: string]: unknown;
}
