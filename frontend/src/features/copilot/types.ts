export interface CopilotResponse {
  status: string;
  request_id?: string;
  case_id?: string;
  summary?: string | null;
  explanation?: string | null;
  finding_explanations?: Array<{
    finding_id: string;
    explanation: string;
  }>;
  mitre_explanations?: Array<{
    technique_id: string;
    technique_name: string;
    explanation: string;
  }>;
  hypothesis_explanations?: Array<{
    hypothesis_id: string;
    explanation: string;
  }>;
  root_cause_explanations?: Array<{
    root_cause_id: string;
    explanation: string;
  }>;
  impact_explanations?: Array<{
    impact_id: string;
    explanation: string;
  }>;
  investigator_answers?: Record<string, string>;
  limitations?: string | null;
  response?: string | null;
  suggested_actions?: string[];
  mitre_techniques?: string[];
  error?: string | null;
  processing_time_ms?: number;
}
