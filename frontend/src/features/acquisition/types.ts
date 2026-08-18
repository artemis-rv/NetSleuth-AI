export interface AcquisitionResponse {
  acquisition_id: string;
  case_id: string;
  file_name: string;
  file_size: number;
  sha256: string;
  format: string;
  source_type: string;
  capture_interface: string | null;
  capture_filter: string | null;
  source_environment: string | null;
  capture_started_at: string | null;
  capture_ended_at: string | null;
  status: 'uploading' | 'processing' | 'complete' | 'failed';
  ingested_at: string;
}

export interface EvidenceResponse {
  evidence_id: string;
  acquisition_id: string;
  file_name: string;
  size_bytes: number | null;
  sha256: string;
  format: string;
  status: string;
  integrity_status: 'pending' | 'verified' | 'mismatch' | 'error' | 'missing';
  registered_at: string;
}

export interface VerifyEvidenceResponse {
  verified: boolean;
  expected_hash: string;
  actual_hash: string;
  status: string;
  message: string;
}
