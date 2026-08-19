import { useQuery } from '@tanstack/react-query';
import { investigationKeys } from './query-keys';
import {
  getTimeline,
  getEntities,
  getRelationships,
  getBehaviors,
  getMitre,
  getGraph,
  getAttackChain,
  getHypotheses,
  getHypothesisValidations,
  getRootCauses,
  getImpactAssessments,
} from './api';
import type { PaginationFilters } from './types';

export function useTimelineQuery(caseId: string, filters: PaginationFilters = {}) {
  return useQuery({
    queryKey: investigationKeys.timeline(caseId, filters as Record<string, unknown>),
    queryFn: () => getTimeline(caseId, filters),
    enabled: !!caseId,
  });
}

export function useEntitiesQuery(caseId: string, filters: PaginationFilters = {}) {
  return useQuery({
    queryKey: investigationKeys.entities(caseId, filters as Record<string, unknown>),
    queryFn: () => getEntities(caseId, filters),
    enabled: !!caseId,
  });
}

export function useRelationshipsQuery(caseId: string, filters: PaginationFilters = {}) {
  return useQuery({
    queryKey: investigationKeys.relationships(caseId, filters as Record<string, unknown>),
    queryFn: () => getRelationships(caseId, filters),
    enabled: !!caseId,
  });
}

export function useBehaviorsQuery(caseId: string, filters: PaginationFilters = {}) {
  return useQuery({
    queryKey: investigationKeys.behaviors(caseId, filters as Record<string, unknown>),
    queryFn: () => getBehaviors(caseId, filters),
    enabled: !!caseId,
  });
}

export function useMitreQuery(caseId: string, filters: PaginationFilters = {}) {
  return useQuery({
    queryKey: investigationKeys.mitre(caseId, filters as Record<string, unknown>),
    queryFn: () => getMitre(caseId, filters),
    enabled: !!caseId,
  });
}

export function useGraphQuery(caseId: string) {
  return useQuery({
    queryKey: investigationKeys.graph(caseId),
    queryFn: () => getGraph(caseId),
    enabled: !!caseId,
  });
}

export function useAttackChainQuery(caseId: string) {
  return useQuery({
    queryKey: investigationKeys.attackChain(caseId),
    queryFn: () => getAttackChain(caseId),
    enabled: !!caseId,
  });
}

export function useHypothesesQuery(caseId: string, filters: PaginationFilters = {}) {
  return useQuery({
    queryKey: investigationKeys.hypotheses(caseId, filters as Record<string, unknown>),
    queryFn: () => getHypotheses(caseId, filters),
    enabled: !!caseId,
  });
}

export function useHypothesisValidationsQuery(caseId: string, filters: PaginationFilters = {}) {
  return useQuery({
    queryKey: investigationKeys.hypothesisValidations(caseId, filters as Record<string, unknown>),
    queryFn: () => getHypothesisValidations(caseId, filters),
    enabled: !!caseId,
  });
}

export function useRootCausesQuery(caseId: string, filters: PaginationFilters = {}) {
  return useQuery({
    queryKey: investigationKeys.rootCauses(caseId, filters as Record<string, unknown>),
    queryFn: () => getRootCauses(caseId, filters),
    enabled: !!caseId,
  });
}

export function useImpactAssessmentsQuery(caseId: string, filters: PaginationFilters = {}) {
  return useQuery({
    queryKey: investigationKeys.impactAssessments(caseId, filters as Record<string, unknown>),
    queryFn: () => getImpactAssessments(caseId, filters),
    enabled: !!caseId,
  });
}
