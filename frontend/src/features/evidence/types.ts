/**
 * Evidence & Custody domain types — derived from openapi-v1.json schemas:
 * EvidenceResponse, EvidenceItemResponse, EvidenceVerificationResponse, CustodyEventResponse.
 */

export interface EvidenceResponse {
  evidence_id: string;
  acquisition_id: string;
  file_name: string;
  size_bytes: number | null;
  sha256: string;
  format: string;
  status: string;
  registered_at: string;
}

export interface EvidenceListResponse {
  items: EvidenceResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface EvidenceItemResponse {
  case_id: string;
  evidence_id: string | null;
  label: string;
  description: string | null;
  evidence_type: string;
  sha256: string | null;
  evidence_item_id: string;
  minio_bucket: string | null;
  object_key: string | null;
  registered_at: string;
  registered_by: string | null;
}

export interface EvidenceItemListResponse {
  items: EvidenceItemResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface EvidenceVerificationResponse {
  evidence_id: string;
  expected_sha256: string;
  observed_sha256: string | null;
  integrity_status: string;
}

export interface CustodyEventResponse {
  custody_event_id: string;
  evidence_item_id: string;
  action: string;
  notes: string | null;
  event_metadata: Record<string, unknown> | null;
  actor_id: string | null;
  actor_name: string | null;
  occurred_at: string;
}

export interface CustodyEventListResponse {
  items: CustodyEventResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface EvidenceFilters {
  page?: number;
  page_size?: number;
}
