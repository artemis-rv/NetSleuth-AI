import { apiClient } from '../../api/client';
import type { CopilotResponse } from './types';

export async function generateSummary(caseId: string): Promise<CopilotResponse> {
  return apiClient<CopilotResponse>(`/api/v1/copilot/${caseId}/summary`, {
    method: 'POST',
  });
}

export async function generateFindingExplanation(caseId: string, findingId: string): Promise<CopilotResponse> {
  return apiClient<CopilotResponse>(`/api/v1/copilot/${caseId}/finding/${findingId}`, {
    method: 'POST',
  });
}

export async function generateMitreExplanation(caseId: string, techniqueId: string): Promise<CopilotResponse> {
  return apiClient<CopilotResponse>(`/api/v1/copilot/${caseId}/mitre/${techniqueId}`, {
    method: 'POST',
  });
}

export async function generateHypothesisExplanation(caseId: string, hypothesisId: string): Promise<CopilotResponse> {
  return apiClient<CopilotResponse>(`/api/v1/copilot/${caseId}/hypothesis/${hypothesisId}`, {
    method: 'POST',
  });
}

export async function generateRootCauseExplanation(caseId: string, rootCauseId: string): Promise<CopilotResponse> {
  return apiClient<CopilotResponse>(`/api/v1/copilot/${caseId}/root-cause/${rootCauseId}`, {
    method: 'POST',
  });
}

export async function generateImpactExplanation(caseId: string, impactId: string): Promise<CopilotResponse> {
  return apiClient<CopilotResponse>(`/api/v1/copilot/${caseId}/impact/${impactId}`, {
    method: 'POST',
  });
}

export async function generateQA(caseId: string, question: string): Promise<CopilotResponse> {
  return apiClient<CopilotResponse>(`/api/v1/copilot/${caseId}/ask`, {
    method: 'POST',
    body: JSON.stringify({ question }),
  });
}
