import { apiClient } from '../../api/client';
import type {
  TimelineEventListResponse,
  EntityListResponse,
  EntityResponse,
  RelationshipListResponse,
  RelationshipResponse,
  BehaviorListResponse,
  MitreMappingListResponse,
  GraphResponse,
  AttackChainResponse,
  PaginationFilters,
} from './types';

/**
 * GET /api/v1/cases/{case_id}/timeline
 */
export async function getTimeline(
  caseId: string,
  filters: PaginationFilters = {},
): Promise<TimelineEventListResponse> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  return apiClient<TimelineEventListResponse>(`/api/v1/cases/${caseId}/timeline`, { params });
}

/**
 * GET /api/v1/cases/{case_id}/entities
 */
export async function getEntities(
  caseId: string,
  filters: PaginationFilters = {},
): Promise<EntityListResponse> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  return apiClient<EntityListResponse>(`/api/v1/cases/${caseId}/entities`, { params });
}

/**
 * GET /api/v1/entities/{entity_id}
 */
export async function getEntity(entityId: string): Promise<EntityResponse> {
  return apiClient<EntityResponse>(`/api/v1/entities/${entityId}`);
}

/**
 * GET /api/v1/cases/{case_id}/relationships
 */
export async function getRelationships(
  caseId: string,
  filters: PaginationFilters = {},
): Promise<RelationshipListResponse> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  return apiClient<RelationshipListResponse>(`/api/v1/cases/${caseId}/relationships`, { params });
}

/**
 * GET /api/v1/relationships/{relationship_id}
 */
export async function getRelationship(relationshipId: string): Promise<RelationshipResponse> {
  return apiClient<RelationshipResponse>(`/api/v1/relationships/${relationshipId}`);
}

/**
 * GET /api/v1/cases/{case_id}/behaviors
 */
export async function getBehaviors(
  caseId: string,
  filters: PaginationFilters = {},
): Promise<BehaviorListResponse> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  return apiClient<BehaviorListResponse>(`/api/v1/cases/${caseId}/behaviors`, { params });
}

/**
 * GET /api/v1/cases/{case_id}/behaviors/{behavior_id}
 */
export async function getBehaviorDetail(
  caseId: string,
  behaviorId: string
): Promise<import('./types').BehaviorDetailResponse> {
  return apiClient<import('./types').BehaviorDetailResponse>(`/api/v1/cases/${caseId}/behaviors/${behaviorId}`);
}

/**
 * GET /api/v1/cases/{case_id}/mitre
 */
export async function getMitre(
  caseId: string,
  filters: PaginationFilters = {},
): Promise<MitreMappingListResponse> {
  const params: Record<string, string> = {};
  if (filters.page !== undefined) params.page = String(filters.page);
  if (filters.page_size !== undefined) params.page_size = String(filters.page_size);
  return apiClient<MitreMappingListResponse>(`/api/v1/cases/${caseId}/mitre`, { params });
}

/**
 * GET /api/v1/cases/{case_id}/graph
 */
export async function getGraph(caseId: string): Promise<GraphResponse> {
  return apiClient<GraphResponse>(`/api/v1/cases/${caseId}/graph`);
}

/**
 * GET /api/v1/cases/{case_id}/attack-chain
 */
export async function getAttackChain(caseId: string): Promise<AttackChainResponse> {
  return apiClient<AttackChainResponse>(`/api/v1/cases/${caseId}/attack-chain`);
}
