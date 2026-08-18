import { describe, it, expect, vi, beforeEach } from 'vitest';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { MemoryRouter } from 'react-router-dom';
import React from 'react';
import '@testing-library/jest-dom';

vi.mock('../api', () => ({
  getCases: vi.fn(),
  getCase: vi.fn(),
  createCase: vi.fn(),
  updateCase: vi.fn(),
}));

import * as caseApi from '../api';
import { CreateCaseForm } from '../components/CreateCaseForm';
import { EditCaseForm } from '../components/EditCaseForm';
import { ApiError } from '../../../api/errors';

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
      <MemoryRouter>
        {children}
      </MemoryRouter>
    </QueryClientProvider>
  );
}

const mockCase = {
  case_id: '123e4567-e89b-12d3-a456-426614174000',
  title: 'Suspicious Lateral Movement',
  description: 'Detected unusual SMB traffic',
  status: 'OPEN',
  priority: 'HIGH',
  trigger_type: 'ANOMALY_DETECTION',
  trigger_description: 'High volume SMB connections',
  external_case_id: 'EXT-99',
  external_system: 'Jira',
  reported_by: 'SOC-Automator',
  investigation_goals: ['Isolate source host', 'Capture PCAP evidence'],
  opened_at: '2026-08-18T10:00:00Z',
  updated_at: '2026-08-18T10:00:00Z',
};

describe('CreateCaseForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders required form elements and accessible labels', () => {
    render(
      <Wrapper>
        <CreateCaseForm />
      </Wrapper>
    );

    expect(screen.getByLabelText(/title/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/trigger type/i)).toBeInTheDocument();
    expect(screen.getByLabelText(/trigger description/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /create investigation/i })).toBeInTheDocument();
  });

  it('validates required fields locally before submission', async () => {
    const user = userEvent.setup();
    render(
      <Wrapper>
        <CreateCaseForm />
      </Wrapper>
    );

    const submitBtn = screen.getByRole('button', { name: /create investigation/i });
    await user.click(submitBtn);

    expect(screen.getByText('Title is required')).toBeInTheDocument();
    expect(screen.getByText('Trigger type is required')).toBeInTheDocument();
    expect(caseApi.createCase).not.toHaveBeenCalled();
  });

  it('submits valid form data including goals and trigger details', async () => {
    const user = userEvent.setup();
    (caseApi.createCase as any).mockResolvedValue(mockCase);

    render(
      <Wrapper>
        <CreateCaseForm />
      </Wrapper>
    );

    await user.type(screen.getByLabelText(/^title/i), 'Exfiltration Investigation');
    await user.selectOptions(screen.getByLabelText(/trigger type/i), 'USER_REPORT');
    await user.type(screen.getByLabelText(/trigger description/i), 'User reported suspicious email with payload');
    
    // Add goal
    const goalInput = screen.getByLabelText(/investigation goal 1/i);
    await user.type(goalInput, 'Identify phishing link');

    const addGoalBtn = screen.getByRole('button', { name: /add goal/i });
    await user.click(addGoalBtn);

    const goalInput2 = screen.getByLabelText(/investigation goal 2/i);
    await user.type(goalInput2, 'Determine if credentials compromised');

    const submitBtn = screen.getByRole('button', { name: /create investigation/i });
    await user.click(submitBtn);

    await waitFor(() => {
      expect(caseApi.createCase).toHaveBeenCalledWith(
        expect.objectContaining({
          title: 'Exfiltration Investigation',
          trigger_type: 'USER_REPORT',
          trigger_description: 'User reported suspicious email with payload',
          investigation_goals: ['Identify phishing link', 'Determine if credentials compromised'],
        })
      );
    });
  });

  it('handles 403 Forbidden error from backend gracefully', async () => {
    const user = userEvent.setup();
    (caseApi.createCase as any).mockRejectedValue(new ApiError('Forbidden', 403, 'FORBIDDEN'));

    render(
      <Wrapper>
        <CreateCaseForm />
      </Wrapper>
    );

    await user.type(screen.getByLabelText(/^title/i), 'Denied Case');
    await user.selectOptions(screen.getByLabelText(/trigger type/i), 'USER_REPORT');

    await user.click(screen.getByRole('button', { name: /create investigation/i }));

    await waitFor(() => {
      expect(screen.getByText(/you do not have permission to create investigations/i)).toBeInTheDocument();
    });
  });

  it('maps 422 validation errors from backend to field errors', async () => {
    const user = userEvent.setup();
    (caseApi.createCase as any).mockRejectedValue(
      new ApiError('Unprocessable Entity', 422, 'VALIDATION_ERROR', undefined, [
        { loc: ['body', 'title'], msg: 'Title too short', type: 'value_error' },
      ])
    );

    render(
      <Wrapper>
        <CreateCaseForm />
      </Wrapper>
    );

    await user.type(screen.getByLabelText(/^title/i), 'Short');
    await user.selectOptions(screen.getByLabelText(/trigger type/i), 'USER_REPORT');

    await user.click(screen.getByRole('button', { name: /create investigation/i }));

    await waitFor(() => {
      expect(screen.getByText('Title too short')).toBeInTheDocument();
    });
  });
});

describe('EditCaseForm', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('populates fields from existing case data', () => {
    render(
      <Wrapper>
        <EditCaseForm caseData={mockCase} />
      </Wrapper>
    );

    expect(screen.getByLabelText(/^title/i)).toHaveValue('Suspicious Lateral Movement');
    expect(screen.getByLabelText(/^description$/i)).toHaveValue('Detected unusual SMB traffic');
    expect(screen.getByLabelText(/trigger description/i)).toHaveValue('High volume SMB connections');
    expect(screen.getByLabelText(/^status/i)).toHaveValue('OPEN');
    expect(screen.getByLabelText(/^priority/i)).toHaveValue('HIGH');
  });

  it('submits updated values via updateCase mutation', async () => {
    const user = userEvent.setup();
    const onSuccess = vi.fn();
    (caseApi.updateCase as any).mockResolvedValue({
      ...mockCase,
      status: 'ACTIVE',
      title: 'Updated Lateral Movement Title',
    });

    render(
      <Wrapper>
        <EditCaseForm caseData={mockCase} onSuccess={onSuccess} />
      </Wrapper>
    );

    const titleInput = screen.getByLabelText(/^title/i);
    await user.clear(titleInput);
    await user.type(titleInput, 'Updated Lateral Movement Title');
    await user.selectOptions(screen.getByLabelText(/^status/i), 'ACTIVE');

    const saveBtn = screen.getByRole('button', { name: /save changes/i });
    await user.click(saveBtn);

    await waitFor(() => {
      expect(caseApi.updateCase).toHaveBeenCalledWith(
        mockCase.case_id,
        expect.objectContaining({
          title: 'Updated Lateral Movement Title',
          status: 'ACTIVE',
        })
      );
      expect(onSuccess).toHaveBeenCalled();
    });
  });
});
