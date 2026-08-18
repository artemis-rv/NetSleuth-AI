import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import '@testing-library/jest-dom';
import { CopilotPanel } from '../components/CopilotPanel';

describe('CopilotPanel Component', () => {
  it('renders official status panel indicating backend API contract gap per directive', () => {
    render(<CopilotPanel caseId="c-123" />);

    expect(screen.getByText('NetSleuth AI Copilot')).toBeInTheDocument();
    expect(screen.getByText(/Copilot API Unavailable \/ Contract Not Configured/i)).toBeInTheDocument();
    expect(screen.getByText(/Why is this case suspicious\?/i)).toBeInTheDocument();
  });
});
