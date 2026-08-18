export interface CopilotResponse {
  status: string;
  request_id?: string;
  case_id?: string;
  summary?: string | null;
  explanation?: string | null;
  investigator_answers?: Record<string, string>;
  limitations?: string | null;
  mitre_explanations?: Array<{
    technique_id: string;
    technique_name: string;
    explanation: string;
  }>;
  response?: string | null;
  suggested_actions?: string[];
  mitre_techniques?: string[];
  error?: string | null;
  processing_time_ms?: number;
}
