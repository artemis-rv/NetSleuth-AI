/**
 * Finding domain types — derived from openapi-v1.json schemas:
 * FindingListItem, FindingDetailResponse, FindingListResponse.
 */

export interface FindingListItem {
  finding_id: string;
  activity: string;
  decision_state: string;
  risk_score: number | null;
  confidence: number | null;
  severity: string;
  detection_method: string;
  first_seen: string | null;
  last_seen: string | null;
  detected_at: string;
}

export interface FindingDetailResponse {
  finding_id: string;
  activity: string;
  decision_state: string;
  risk_score: number | null;
  confidence: number | null;
  severity: string;
  detection_method: string;
  first_seen: string | null;
  last_seen: string | null;
  detected_at: string;
  package_id: string;
  acquisition_id: string;
  anomaly_score: number | null;
  anomaly_detected: boolean;
  risk_policy_version: string | null;
  classification_probabilities: Record<string, number> | null;
  feature_attribution: Record<string, number> | null;
  rationale: string | null;
  model_version: string | null;
  feature_schema_version: string | null;
  version: number;
  supersedes_id: string | null;
}

export interface FindingListResponse {
  items: FindingListItem[];
  total: number;
  page: number;
  page_size: number;
}

export interface FindingsFilters {
  page?: number;
  page_size?: number;
  activity?: string;
  decision_state?: string;
  min_risk?: number;
}
