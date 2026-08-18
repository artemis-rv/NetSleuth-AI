export interface CopilotResponse {
  status: string;
  response: string | null;
  suggested_actions: string[];
  mitre_techniques: string[];
  error: string | null;
  processing_time_ms: number;
}
