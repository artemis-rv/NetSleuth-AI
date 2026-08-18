import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { CopilotPanel } from '../components/CopilotPanel';

window.HTMLElement.prototype.scrollIntoView = vi.fn();
// Mock the copilot API module
vi.mock('../api', () => ({
  generateQA: vi.fn().mockResolvedValue({
    status: 'SUCCESS',
    response: 'This case shows signs of C2 beaconing based on regular interval connections.',
    suggested_actions: [],
    mitre_techniques: [],
    error: null,
    processing_time_ms: 350,
  }),
}));

function renderWithQueryClient(ui: React.ReactElement) {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <QueryClientProvider client={queryClient}>{ui}</QueryClientProvider>
  );
}

describe('CopilotPanel Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders header and case reference', () => {
    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    expect(screen.getByText('NetSleuth AI Copilot')).toBeInTheDocument();
    expect(screen.getByText(/c-123/i)).toBeInTheDocument();
  });

  it('renders preset investigator prompts in the default (empty) state', () => {
    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    expect(screen.getByText(/Why is this case suspicious\?/i)).toBeInTheDocument();
    expect(screen.getByText(/What are the highest-risk findings\?/i)).toBeInTheDocument();
    expect(screen.getByText(/Preset Investigator Queries/i)).toBeInTheDocument();
  });

  it('selecting a preset populates the input field', () => {
    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    const presetBtn = screen.getByText(/Why is this case suspicious\?/i);
    fireEvent.click(presetBtn);
    const input = screen.getByPlaceholderText(/Ask AI Copilot about this case/i);
    expect((input as HTMLInputElement).value).toBe('Why is this case suspicious?');
  });

  it('renders input field and Send button', () => {
    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    expect(screen.getByPlaceholderText(/Ask AI Copilot about this case/i)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: /send/i })).toBeInTheDocument();
  });

  it('Send button is disabled when input is empty', () => {
    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    const sendBtn = screen.getByRole('button', { name: /send/i });
    expect(sendBtn).toBeDisabled();
  });
});
