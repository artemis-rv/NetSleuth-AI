import { apiClient } from '../../api/client';
import type { AnalysisJobResponse } from './types';
import type { PaginatedList } from '../acquisition/api'; // Reuse PaginatedList

export async function startAnalysis(caseId: string, acquisitionId: string): Promise<AnalysisJobResponse> {
  return apiClient<AnalysisJobResponse>(`/api/v1/cases/${caseId}/analysis`, {
    method: 'POST',
    body: JSON.stringify({ acquisition_id: acquisitionId }),
  });
}

export async function getAnalysisJobs(caseId: string, page = 1, pageSize = 25): Promise<PaginatedList<AnalysisJobResponse>> {
  return apiClient<PaginatedList<AnalysisJobResponse>>(`/api/v1/cases/${caseId}/analysis`, {
    method: 'GET',
    params: {
      page: page.toString(),
      page_size: pageSize.toString(),
    },
  });
}

export async function getAnalysisJob(caseId: string, analysisId: string): Promise<AnalysisJobResponse> {
  return apiClient<AnalysisJobResponse>(`/api/v1/cases/${caseId}/analysis/${analysisId}`, {
    method: 'GET',
  });
}
