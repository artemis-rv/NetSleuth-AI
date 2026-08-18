// Types derived from docs/api/openapi-v1.json
// CaseResponse, CreateCaseRequest, UpdateCaseRequest, PaginatedResponse

export interface CaseResponse {
  case_id: string;
  title: string;
  description?: string | null;
  status: string;
  priority?: string | null;
  trigger_type: string;
  trigger_description?: string | null;
  external_case_id?: string | null;
  external_system?: string | null;
  reported_by?: string | null;
  investigation_goals?: string[] | null;
  opened_at: string;
  closed_at?: string | null;
  created_by?: string | null;
  updated_at: string;
}

export interface CreateCaseRequest {
  title: string;
  trigger_type: string;
  description?: string | null;
  trigger_description?: string | null;
  investigation_goals?: string[] | null;
  external_case_id?: string | null;
  external_system?: string | null;
  reported_by?: string | null;
  priority?: string | null;
}

export interface UpdateCaseRequest {
  title?: string | null;
  description?: string | null;
  priority?: string | null;
  trigger_type?: string | null;
  trigger_description?: string | null;
  investigation_goals?: string[] | null;
  external_case_id?: string | null;
  external_system?: string | null;
  reported_by?: string | null;
  status?: string | null;
}

export interface PaginatedCases {
  items: CaseResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface CasesFilters {
  page?: number;
  page_size?: number;
  status?: string;
  priority?: string;
  sort_by?: 'created_at' | 'updated_at' | 'priority' | 'status';
}

// Enum-like constants matching backend values
export const CASE_STATUSES = [
  'OPEN',
  'ACTIVE',
  'UNDER_REVIEW',
  'CLOSED',
  'ARCHIVED',
] as const;

export type CaseStatus = typeof CASE_STATUSES[number];

export const CASE_PRIORITIES = [
  'CRITICAL',
  'HIGH',
  'MEDIUM',
  'LOW',
] as const;

export type CasePriority = typeof CASE_PRIORITIES[number];

export const TRIGGER_TYPES = [
  'USER_REPORT',
  'AUTOMATED_ALERT',
  'THREAT_INTELLIGENCE',
  'ANOMALY_DETECTION',
  'COMPLIANCE_AUDIT',
  'INCIDENT_RESPONSE',
  'ROUTINE_INVESTIGATION',
  'OTHER',
] as const;

export type TriggerType = typeof TRIGGER_TYPES[number];
