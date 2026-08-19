/**
 * Investigation domain types — derived from openapi-v1.json schemas:
 * EntityResponse, RelationshipResponse, BehaviorResponse, TimelineEventResponse,
 * MitreMappingResponse, GraphResponse, AttackChainResponse.
 */

export interface EntityResponse {
  entity_id: string;
  case_id: string;
  name: string;
  entity_type: string;
  risk_score: number | null;
  properties: Record<string, unknown> | null;
  created_at: string;
}

export interface EntityListResponse {
  items: EntityResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface RelationshipResponse {
  relationship_id: string;
  case_id: string;
  source_entity_id: string;
  target_entity_id: string;
  relationship_type: string;
  confidence: number | null;
  properties: Record<string, unknown> | null;
  created_at: string;
}

export interface RelationshipListResponse {
  items: RelationshipResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface BehaviorResponse {
  behavior_id: string;
  case_id: string;
  name: string;
  description: string | null;
  category: string;
  severity: string;
  confidence: number | null;
  first_observed: string;
  last_observed: string;
}

export interface BehaviorListResponse {
  items: BehaviorResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface TimelineEventResponse {
  timeline_event_id: string;
  case_id: string;
  event_type: string;
  title?: string | null;
  // Nullable — DB column allows NULL, backend Optional[str]
  description: string | null;
  event_timestamp: string;
  source_id: string | null;
  finding_id?: string | null;
  attributes?: Record<string, unknown> | null;
  created_at: string;
}

export interface TimelineEventListResponse {
  items: TimelineEventResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface MitreMappingResponse {
  mitre_mapping_id: string;
  case_id: string;
  tactic_id: string;
  tactic_name: string;
  technique_id: string;
  technique_name: string;
  confidence: number | null;
  rationale?: string | null;
  justification?: string | null;
  finding_ids?: string[];
  mapped_at: string;
}

export interface MitreMappingListResponse {
  items: MitreMappingResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface GraphResponse {
  nodes: EntityResponse[];
  edges: RelationshipResponse[];
}

export interface AttackChainResponse {
  chain_id: string;
  case_id: string;
  title?: string;
  summary?: string;
  stages: Record<string, unknown>;
  confidence: number | null;
  created_at: string;
  updated_at: string;
}

export interface PaginationFilters {
  page?: number;
  page_size?: number;
}
