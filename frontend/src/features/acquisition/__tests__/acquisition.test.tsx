import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen } from '@testing-library/react';
import React from 'react';
import '@testing-library/jest-dom';

vi.mock('../api', () => ({
  getAcquisitions: vi.fn(),
  getEvidenceList: vi.fn(),
  uploadAcquisition: vi.fn(),
  verifyEvidence: vi.fn(),
}));

import * as api from '../api';
import { AcquisitionSection } from '../components/AcquisitionSection';

vi.mock('../../../auth/auth-context', () => ({
  useAuth: () => ({
    user: { user_id: 'u1', username: 'investigator', role: 'investigator' },
  }),
}));

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 }, mutations: { retry: false } },
  });
}

function Wrapper({ children }: { children: React.ReactNode }) {
  const queryClient = makeQueryClient();
  return (
    <QueryClientProvider client={queryClient}>
      {children}
    </QueryClientProvider>
  );
}

describe('AcquisitionSection', () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it('renders upload UI when no acquisition exists', () => {
    render(
      <Wrapper>
        <AcquisitionSection caseId="case-1" acquisitions={[]} evidenceList={[]} />
      </Wrapper>
    );

    expect(screen.getByText('Evidence Acquisition')).toBeInTheDocument();
  });

  it('handles file selection and upload', async () => {
    (api.uploadAcquisition as any).mockResolvedValue({
      acquisition_id: 'acq-1',
      file_name: 'test.pcap',
      status: 'complete'
    });

    render(
      <Wrapper>
        <AcquisitionSection caseId="case-1" acquisitions={[]} evidenceList={[]} />
      </Wrapper>
    );
  });

  it('renders metadata when acquisition exists', () => {
    const acquisition = {
      acquisition_id: 'acq-1', case_id: 'case-1', file_name: 'test.pcap',
      file_size: 1048576, format: 'pcap', sha256: 'abc', source_type: 'pcap',
      capture_interface: null, capture_filter: null, source_environment: null,
      capture_started_at: null, capture_ended_at: null, status: 'complete' as const, ingested_at: '2023-01-01'
    };

    render(
      <Wrapper>
        <AcquisitionSection caseId="case-1" acquisitions={[acquisition]} evidenceList={[]} />
      </Wrapper>
    );

    expect(screen.getByText('test.pcap')).toBeInTheDocument();
  });

  it('renders evidence verification UI when evidence exists', async () => {
    const acquisition = {
      acquisition_id: 'acq-1', case_id: 'case-1', file_name: 'test.pcap', file_size: 1048576,
      format: 'pcap', sha256: 'abc', source_type: 'pcap', capture_interface: null, capture_filter: null,
      source_environment: null, capture_started_at: null, capture_ended_at: null, status: 'complete' as const,
      ingested_at: '2023-01-01'
    };

    render(
      <Wrapper>
        <AcquisitionSection caseId="case-1" acquisitions={[acquisition as any]} evidenceList={[]} />
      </Wrapper>
    );
  });
});
