import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';
import '@testing-library/jest-dom';

vi.mock('../api', () => ({
  getSystemStatus: vi.fn(),
}));

import * as adminApi from '../api';
import { AdminPage } from '../pages/AdminPage';

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

const mockSystemStatus = {
  status: 'HEALTHY',
  environment: 'production',
  version: '1.0.0',
};

describe('AdminPage Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders system status and role access policy cards', async () => {
    vi.mocked(adminApi.getSystemStatus).mockResolvedValueOnce(mockSystemStatus);

    render(
      <Wrapper>
        <AdminPage />
      </Wrapper>
    );

    await waitFor(() => {
      expect(screen.getByText('System Administration')).toBeInTheDocument();
      expect(screen.getByText('HEALTHY')).toBeInTheDocument();
      expect(screen.getByText('Frontend Role Access Policy')).toBeInTheDocument();
    });
  });
});
