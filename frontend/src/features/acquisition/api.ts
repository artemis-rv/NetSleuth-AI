import { apiClient } from '../../api/client';
import type { AcquisitionResponse, EvidenceResponse, VerifyEvidenceResponse } from './types';


export interface PaginatedList<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export async function uploadAcquisition(caseId: string, files: File[]): Promise<AcquisitionResponse[]> {
  const formData = new FormData();
  files.forEach(file => {
    formData.append('files', file);
  });
  
  return apiClient<AcquisitionResponse[]>(`/api/v1/cases/${caseId}/acquisitions`, {
    method: 'POST',
    body: formData,
    // Note: Do not set Content-Type header manually when sending FormData,
    // fetch will automatically set it to multipart/form-data with the correct boundary.
  });
}

export async function getAcquisitions(caseId: string, page = 1, pageSize = 25): Promise<PaginatedList<AcquisitionResponse>> {
  return apiClient<PaginatedList<AcquisitionResponse>>(`/api/v1/cases/${caseId}/acquisitions`, {
    method: 'GET',
    params: {
      page: page.toString(),
      page_size: pageSize.toString(),
    },
  });
}

export async function getEvidenceList(caseId: string, page = 1, pageSize = 25): Promise<PaginatedList<EvidenceResponse>> {
  return apiClient<PaginatedList<EvidenceResponse>>(`/api/v1/cases/${caseId}/evidence`, {
    method: 'GET',
    params: {
      page: page.toString(),
      page_size: pageSize.toString(),
    },
  });
}

export async function verifyEvidence(evidenceId: string): Promise<VerifyEvidenceResponse> {
  return apiClient<VerifyEvidenceResponse>(`/api/v1/evidence/${evidenceId}/verify`, {
    method: 'POST',
  });
}
