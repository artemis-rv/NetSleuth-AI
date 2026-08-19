/**
 * Investigation domain types — derived from openapi-v1.json schemas:
 * EntityResponse, RelationshipResponse, BehaviorResponse, TimelineEventResponse,
 * MitreMappingResponse, GraphResponse, AttackChainResponse.
 *
 * V1.3 Assessment types: HypothesisResponse, HypothesisValidationResponse,
 * RootCauseResponse, ImpactAssessmentResponse.
 */

export interface EntityResponse {
  entity_id: string;
  case_id: string;
  // M3-003 FIX: V1.3 contract uses 'label', not 'name'
  label: string;
  entity_type: string;
  risk_score: number | null;
  properties: Record<string, unknown> | null;
  first_seen: string | null;
  last_seen: string | null;
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
  // M3: V1.3 contract uses 'label', not 'name'
  label: string | null;
  description: string | null;
  // M3: V1.3 contract uses 'behavior_type', not 'category'
  behavior_type: string | null;
  severity: string | null;
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
  // M3-002a: V1.3 contract field
  mapping_status: string | null;
  confidence: number | null;
  rationale?: string | null;
  justification?: string | null;
  finding_ids?: string[];
  behavior_id?: string | null;
  source_finding_ids?: string[] | null;
  evidence_ids?: string[] | null;
  detection_strategy_ids?: string[] | null;
  analytic_ids?: string[] | null;
  data_component_ids?: string[] | null;
  channels?: string[] | null;
  first_seen?: string | null;
  last_seen?: string | null;
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

// M3-006 FIX: stages is an array, not Record<string, unknown>
export interface AttackChainStage {
  stage_id?: string;
  name?: string;
  finding_ids?: string[];
  event_ids?: string[];
  timestamp?: string;
  technique_id?: string;
  [key: string]: unknown;
}

export interface AttackChainResponse {
  // M3-005 FIX: Use DB column name 'attack_chain_id' instead of 'chain_id'
  attack_chain_id: string;
  case_id: string;
  // M3-008 FIX: V1.3 contract field
  status: string | null;
  title?: string;
  summary?: string;
  // M3-006 FIX: stages is an array
  stages: AttackChainStage[];
  confidence: number | null;
  created_at: string;
  updated_at: string;
}

export interface PaginationFilters {
  page?: number;
  page_size?: number;
}


// ─────────────────────────────────────────────
// V1.3 Assessment Types
// ─────────────────────────────────────────────

export interface HypothesisResponse {
  hypothesis_id: string;
  case_id: string;
  statement: string;
  hypothesis_type: string;
  status: string;
  confidence: number;
  supporting_evidence_ids: string[];
  supporting_finding_ids: string[] | null;
  related_entity_ids: string[] | null;
  related_mitre_mapping_ids: string[] | null;
  first_seen: string | null;
  last_seen: string | null;
  supporting_reasons: string[] | null;
  missing_evidence: string[] | null;
  created_at: string;
}

export interface HypothesisListResponse {
  items: HypothesisResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface HypothesisValidationResponse {
  validation_id: string;
  case_id: string;
  hypothesis_id: string;
  validation_status: string;
  supporting_evidence_ids: string[] | null;
  contradicting_evidence_ids: string[] | null;
  supporting_reasons: string[] | null;
  contradicting_reasons: string[] | null;
  missing_evidence: string[] | null;
  confidence: number;
  validated_at: string;
  created_at: string;
}

export interface HypothesisValidationListResponse {
  items: HypothesisValidationResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface RootCauseResponse {
  root_cause_id: string;
  case_id: string;
  statement: string;
  status: string;
  confidence: number;
  supporting_hypothesis_ids: string[] | null;
  supporting_evidence_ids: string[];
  supporting_finding_ids: string[] | null;
  rationale: string[] | null;
  missing_evidence: string[] | null;
  created_at: string;
}

export interface RootCauseListResponse {
  items: RootCauseResponse[];
  total: number;
  page: number;
  page_size: number;
}

export interface ImpactAssessmentResponse {
  impact_id: string;
  case_id: string;
  category: string;
  statement: string;
  status: string;
  confidence: number;
  supporting_evidence_ids: string[];
  supporting_finding_ids: string[] | null;
  affected_entity_ids: string[] | null;
  rationale: string[] | null;
  missing_evidence: string[] | null;
  created_at: string;
}

export interface ImpactAssessmentListResponse {
  items: ImpactAssessmentResponse[];
  total: number;
  page: number;
  page_size: number;
}
