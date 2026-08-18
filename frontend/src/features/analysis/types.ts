export interface AnalysisJobResponse {
  analysis_id: string;
  case_id: string;
  acquisition_id: string;
  status: 'queued' | 'running' | 'completed' | 'failed' | 'cancelled';
  current_stage: 'QUEUED' | 'M1' | 'M2' | 'M3' | 'M4' | 'COMPLETED' | 'FAILED' | string;
  progress: number | null;
  started_at: string;
  completed_at: string | null;
  error_code?: string;
  error_message?: string;
  created_at: string;
  updated_at: string;
}
