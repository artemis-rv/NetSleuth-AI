// Types derived from docs/api/openapi-v1.json
// CaseResponse, CreateCaseRequest, UpdateCaseRequest, PaginatedResponse

export interface InvestigationGoal {
  id: string;
  description: string;
  completed: boolean;
  note?: string | null;
}

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
  investigation_goals?: Array<InvestigationGoal | string> | null;
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
  investigation_goals?: Array<InvestigationGoal | string> | null;
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
  investigation_goals?: Array<InvestigationGoal | string> | null;
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

export const CASE_STATUSES = [
  'open',
  'active',
  'under_review',
  'closed',
  'archived',
] as const;

export type CaseStatus = typeof CASE_STATUSES[number];

export const CASE_STATUS_LABELS: Record<string, string> = {
  open: 'Open',
  active: 'Active',
  investigating: 'Investigating',
  under_review: 'Under Review',
  review: 'Under Review',
  closed: 'Closed',
  archived: 'Archived',
};

export const CASE_PRIORITIES = [
  'critical',
  'high',
  'medium',
  'low',
] as const;

export type CasePriority = typeof CASE_PRIORITIES[number];

export const CASE_PRIORITY_LABELS: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export const ALLOWED_STATUS_TRANSITIONS: Record<string, string[]> = {
  open: ['open', 'active', 'investigating', 'closed'],
  active: ['active', 'under_review', 'review', 'closed'],
  investigating: ['investigating', 'review', 'under_review', 'closed'],
  under_review: ['under_review', 'review', 'closed', 'active', 'investigating'],
  review: ['review', 'under_review', 'closed', 'investigating', 'active'],
  closed: ['closed', 'open', 'archived'],
  archived: ['archived', 'open', 'closed'],
};

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
