import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';
import '@testing-library/jest-dom';

vi.mock('../api', () => ({
  getCaseReports: vi.fn(),
  getReport: vi.fn(),
}));

import * as reportsApi from '../api';
import { ReportsSection } from '../components/ReportsSection';

function makeQueryClient() {
  return new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
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

const mockReports = {
  items: [
    {
      case_id: 'c-1',
      report_type: 'SUMMARY',
      title: 'Investigation Final Report v1.3',
      format: 'HTML',
      report_id: 'rep-99',
      version: 1,
      minio_bucket: 'reports',
      object_key: 'c-1/report_v1.html',
      sha256: '9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08',
      generated_at: '2026-08-18T12:00:00Z',
      generated_by: 'system',
    },
  ],
  total: 1,
  page: 1,
  page_size: 25,
};

describe('ReportsSection Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders generated report list correctly', async () => {
    vi.mocked(reportsApi.getCaseReports).mockResolvedValueOnce(mockReports);

    render(
      <Wrapper>
        <ReportsSection caseId="c-1" />
      </Wrapper>
    );

    await waitFor(() => {
      expect(screen.getByText('Investigation Final Report v1.3')).toBeInTheDocument();
      expect(screen.getByText('SUMMARY')).toBeInTheDocument();
      expect(screen.getByText('View Details')).toBeInTheDocument();
    });
  });
});
