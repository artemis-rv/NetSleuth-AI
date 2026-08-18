/**
 * Reports domain types — derived from openapi-v1.json schemas:
 * ReportResponse, ReportListResponse.
 */

export interface ReportResponse {
  case_id: string;
  report_type: string;
  title: string | null;
  format: string;
  report_id: string;
  version: number;
  minio_bucket: string;
  object_key: string;
  sha256: string;
  generated_at: string;
  generated_by: string | null;
}

export interface ReportListResponse {
  items: ReportResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface ReportFilters {
  page?: number;
  page_size?: number;
}
