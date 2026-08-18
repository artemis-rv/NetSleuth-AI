import { describe, it, expect, vi, beforeAll } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';
import '@testing-library/jest-dom';

// Mock the API client before any module imports that use it
vi.mock('../../../api/client', () => ({
  apiClient: vi.fn(),
}));

// Mock only the cases hooks module
vi.mock('../../cases/hooks', () => ({
  useCasesQuery: vi.fn(),
}));

import { apiClient } from '../../../api/client';
import * as caseHooks from '../../cases/hooks';
import { AuthProvider } from '../../../auth/auth-context';
import { DashboardPage } from '../DashboardPage';

const mockUser = { user_id: 'u1', username: 'investigator', role: 'investigator' };

beforeAll(() => {
  // Simulate a logged-in user: /auth/me will return the mock user
  (apiClient as any).mockResolvedValue(mockUser);
});

function Wrapper({ children }: { children: React.ReactNode }) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0 } },
  });
  return (
    <QueryClientProvider client={qc}>
      <MemoryRouter>
        <AuthProvider>
          {children}
        </AuthProvider>
      </MemoryRouter>
    </QueryClientProvider>
  );
}

const mockData = {
  items: [
    {
      case_id: 'abc-123',
      title: 'Alpha Incident',
      status: 'OPEN',
      priority: 'HIGH',
      trigger_type: 'USER_REPORT',
      opened_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-10T00:00:00Z',
    },
    {
      case_id: 'def-456',
      title: 'Beta Investigation',
      status: 'ACTIVE',
      priority: 'CRITICAL',
      trigger_type: 'AUTOMATED_ALERT',
      opened_at: '2026-01-02T00:00:00Z',
      updated_at: '2026-01-11T00:00:00Z',
    },
  ],
  total: 12,
  page: 1,
  page_size: 25,
};

describe('DashboardPage', () => {
  it('shows dashboard heading', async () => {
    (caseHooks.useCasesQuery as any).mockReturnValue({
      data: undefined,
      isLoading: true,
      isError: false,
      error: null,
      refetch: vi.fn(),
    });
    render(<Wrapper><DashboardPage /></Wrapper>);
    await waitFor(() => {
      expect(screen.getByText('Dashboard')).toBeInTheDocument();
    });
  });

  it('shows total count from API', async () => {
    (caseHooks.useCasesQuery as any).mockReturnValue({
      data: mockData,
      isLoading: false,
      isError: false,
      error: null,
      refetch: vi.fn(),
    });
    render(<Wrapper><DashboardPage /></Wrapper>);
    await waitFor(() => {
      // Total count from API = 12
      expect(screen.getByText('12')).toBeInTheDocument();
    });
  });

  it('renders recent cases in table', async () => {
    (caseHooks.useCasesQuery as any).mockReturnValue({
      data: mockData,
      isLoading: false,
      isError: false,
      error: null,
      refetch: vi.fn(),
    });
    render(<Wrapper><DashboardPage /></Wrapper>);
    await waitFor(() => {
      expect(screen.getByText('Alpha Incident')).toBeInTheDocument();
      expect(screen.getByText('Beta Investigation')).toBeInTheDocument();
    });
  });

  it('shows empty state when no cases', async () => {
    (caseHooks.useCasesQuery as any).mockReturnValue({
      data: { items: [], total: 0, page: 1, page_size: 25 },
      isLoading: false,
      isError: false,
      error: null,
      refetch: vi.fn(),
    });
    render(<Wrapper><DashboardPage /></Wrapper>);
    await waitFor(() => {
      expect(screen.getByText('No investigations yet')).toBeInTheDocument();
    });
  });

  it('shows error state on API failure', async () => {
    (caseHooks.useCasesQuery as any).mockReturnValue({
      data: undefined,
      isLoading: false,
      isError: true,
      error: new Error('API failed'),
      refetch: vi.fn(),
    });
    render(<Wrapper><DashboardPage /></Wrapper>);
    await waitFor(() => {
      expect(screen.getByText('Something went wrong')).toBeInTheDocument();
    });
  });
});
