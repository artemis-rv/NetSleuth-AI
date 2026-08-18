import { apiClient } from '../../api/client';
import type { CopilotResponse } from './types';

export async function generateSummary(caseId: string): Promise<CopilotResponse> {
  return apiClient<CopilotResponse>(`/api/v1/copilot/${caseId}/summary`, {
    method: 'POST',
  });
}

export async function generateMitreExplanation(caseId: string, techniqueId: string): Promise<CopilotResponse> {
  return apiClient<CopilotResponse>(`/api/v1/copilot/${caseId}/mitre/${techniqueId}`, {
    method: 'POST',
  });
}

export async function generateQA(caseId: string, question: string): Promise<CopilotResponse> {
  return apiClient<CopilotResponse>(`/api/v1/copilot/${caseId}/qa`, {
    method: 'POST',
    body: JSON.stringify({ question }),
  });
}
