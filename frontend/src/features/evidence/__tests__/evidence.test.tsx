import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';
import '@testing-library/jest-dom';

vi.mock('../api', () => ({
  getCaseEvidence: vi.fn(),
  getEvidence: vi.fn(),
  verifyEvidence: vi.fn(),
  getCustodyItems: vi.fn(),
  getCustodyItem: vi.fn(),
  getCustodyEvents: vi.fn(),
}));

import * as evidenceApi from '../api';
import { EvidenceSection } from '../components/EvidenceSection';

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  });
}

function Wrapper({ children }: { children: React.ReactNode }) {
  const qc = makeQueryClient();
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>{children}</MemoryRouter>
    </QueryClientProvider>
  );
}

const mockEvidence = {
  items: [
    {
      evidence_id: 'ev-101',
      acquisition_id: 'acq-1',
      file_name: 'capture_01.pcap',
      size_bytes: 1048576,
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      format: 'PCAP',
      status: 'VERIFIED',
      registered_at: '2026-08-18T10:00:00Z',
    },
  ],
  total: 1,
  page: 1,
  page_size: 25,
};

const mockCustody = {
  items: [
    {
      case_id: 'c-1',
      evidence_id: 'ev-101',
      label: 'Network PCAP Payload 1',
      description: 'Primary capture',
      evidence_type: 'pcap',
      sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      evidence_item_id: 'item-1',
      minio_bucket: 'evidence',
      object_key: 'c-1/capture_01.pcap',
      registered_at: '2026-08-18T10:00:00Z',
      registered_by: 'u-1',
    },
  ],
  total: 1,
  page: 1,
  page_size: 25,
};

describe('EvidenceSection Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders evidence table with items and verify actions', async () => {
    vi.mocked(evidenceApi.getCaseEvidence).mockResolvedValueOnce(mockEvidence);
    vi.mocked(evidenceApi.getCustodyItems).mockResolvedValueOnce(mockCustody);

    render(
      <Wrapper>
        <EvidenceSection caseId="c-1" />
      </Wrapper>
    );

    await waitFor(() => {
      expect(screen.getByText('capture_01.pcap')).toBeInTheDocument();
      expect(screen.getByText('Verify')).toBeInTheDocument();
      expect(screen.getByText('Network PCAP Payload 1')).toBeInTheDocument();
    });
  });
});
