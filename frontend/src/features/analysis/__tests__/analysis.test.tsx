import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import React from 'react';
import '@testing-library/jest-dom';

vi.mock('../api', () => ({
  startAnalysis: vi.fn(),
  getAnalysisJobs: vi.fn(),
  getAnalysisJob: vi.fn(),
}));

import * as api from '../api';
import { AnalysisSection } from '../components/AnalysisSection';

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

describe('AnalysisSection', () => {
  beforeEach(() => {
    vi.resetAllMocks();
    (api.getAnalysisJobs as any).mockResolvedValue({ jobs: [] });
  });

  it('renders prompt if no acquisitionId is provided', () => {
    render(
      <Wrapper>
        <AnalysisSection caseId="case-1" acquisitionId={undefined} />
      </Wrapper>
    );
    expect(screen.getByText(/Please upload an acquisition first/i)).toBeInTheDocument();
  });

  it('renders start button when no active jobs exist', async () => {
    (api.getAnalysisJobs as any).mockResolvedValue({ jobs: [] });
    
    render(
      <Wrapper>
        <AnalysisSection caseId="case-1" acquisitionId="acq-1" />
      </Wrapper>
    );

    // Wait for the query to resolve
    await waitFor(() => {
      expect(screen.getAllByRole('button', { name: /Start Analysis/i })[0]).toBeInTheDocument();
    });
  });

  it('handles start analysis mutation', async () => {
    (api.getAnalysisJobs as any).mockResolvedValue({ jobs: [] });
    (api.startAnalysis as any).mockResolvedValue({ analysis_id: 'job-1', status: 'queued' });

    render(
      <Wrapper>
        <AnalysisSection caseId="case-1" acquisitionId="acq-1" />
      </Wrapper>
    );

    await waitFor(() => {
      expect(screen.getAllByRole('button', { name: /Start Analysis/i })[0]).toBeInTheDocument();
    });

    fireEvent.click(screen.getAllByRole('button', { name: /Start Analysis/i })[0]);

    await waitFor(() => {
      expect(api.startAnalysis).toHaveBeenCalledWith('case-1', 'acq-1');
    });
  });

  it('renders active job timeline', async () => {
    (api.getAnalysisJobs as any).mockResolvedValue({
      jobs: [
        {
          analysis_id: 'job-1', case_id: 'case-1', acquisition_id: 'acq-1',
          status: 'running', current_stage: 'M2_ANALYSIS', progress: 45,
          started_at: '2023-01-01', completed_at: null, error_code: null,
          created_at: '2023-01-01', updated_at: '2023-01-01'
        }
      ]
    });

    render(
      <Wrapper>
        <AnalysisSection caseId="case-1" acquisitionId="acq-1" />
      </Wrapper>
    );

    await waitFor(() => {
      expect(screen.getByText('45%')).toBeInTheDocument();
      expect(screen.getByText('RUNNING')).toBeInTheDocument();
      // Button should not be present since active job exists
      expect(screen.queryByRole('button', { name: /Start Analysis/i })).not.toBeInTheDocument();
    });
  });

  it('renders failure state properly', async () => {
    (api.getAnalysisJobs as any).mockResolvedValue({
      jobs: [
        {
          analysis_id: 'job-1', case_id: 'case-1', acquisition_id: 'acq-1',
          status: 'failed', current_stage: 'M3_CORRELATION', progress: null,
          started_at: '2023-01-01', completed_at: null, error_code: 'ERR_TIMEOUT',
          created_at: '2023-01-01', updated_at: '2023-01-01'
        }
      ]
    });

    render(
      <Wrapper>
        <AnalysisSection caseId="case-1" acquisitionId="acq-1" />
      </Wrapper>
    );

    await waitFor(() => {
      expect(screen.getByText(/Analysis Failed at M3_CORRELATION/i)).toBeInTheDocument();
      expect(screen.getByText('ERR_TIMEOUT')).toBeInTheDocument();
      expect(screen.getByText('FAILED')).toBeInTheDocument();
      // Since it's failed, you can start a new one (assuming backend allows retry/new analysis for same acq)
      expect(screen.getAllByRole('button', { name: /Start Analysis/i })[0]).toBeInTheDocument();
    });
  });
});
