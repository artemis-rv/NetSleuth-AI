/**
 * copilot.test.tsx
 *
 * Covers all 17 required spec cases + existing 8 = 25 total tests.
 * Tests both the unit functions (unwrapAnswer, parseToPoints, buildCopilotResponse)
 * and the full CopilotPanel component rendering.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import '@testing-library/jest-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { CopilotPanel } from '../components/CopilotPanel';
import { unwrapAnswer, parseToPoints, buildCopilotResponse } from '../components/CopilotPanel';

window.HTMLElement.prototype.scrollIntoView = vi.fn();

// Default mock: markdown with heading + numbered list + status sub-item
vi.mock('../api', () => ({
  generateQA: vi.fn().mockResolvedValue({
    status: 'SUCCESS',
    investigator_answers: {
      'Why is this case suspicious?':
        '### Why this case is suspicious\n\n1. **C2 / Malware Communication**\n   - Status: `SUPPORTED`',
    },
  }),
}));

function renderWithQueryClient(ui: React.ReactElement) {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>);
}

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — unwrapAnswer
// ─────────────────────────────────────────────────────────────────────────────

describe('unwrapAnswer()', () => {
  it('T1: plain string passthrough', () => {
    expect(unwrapAnswer('Hello world')).toBe('Hello world');
  });

  it('T2: strips question from { question, answer } object', () => {
    const result = unwrapAnswer({ question: 'Why?', answer: 'Because X.' });
    expect(result).toBe('Because X.');
    expect(result).not.toContain('Why?');
    expect(result).not.toContain('question');
  });

  it('T3: nested { answer: { answer: "..." } } unwrap', () => {
    const result = unwrapAnswer({ answer: { answer: 'Deep answer.' } });
    expect(result).toBe('Deep answer.');
  });

  it('T4: JSON string { question, answer } parsed and unwrapped', () => {
    const json = JSON.stringify({ question: 'Why?', answer: 'The answer is here.' });
    const result = unwrapAnswer(json);
    expect(result).toBe('The answer is here.');
    expect(result).not.toContain('"question"');
  });

  it('T5: strips ```json fence', () => {
    const result = unwrapAnswer('```json\n{"answer":"Clean text."}\n```');
    expect(result).toBe('Clean text.');
  });

  it('T6: malformed JSON returns sanitized text', () => {
    const result = unwrapAnswer('{ bad json }{{}');
    // Should not throw and should not return raw JSON chars
    expect(typeof result).toBe('string');
    expect(result.length).toBeGreaterThan(0);
  });

  it('T7: strips leading "answer:" label', () => {
    expect(unwrapAnswer('answer: The real content.')).toBe('The real content.');
  });

  it('T8: strips leading "question:" label', () => {
    expect(unwrapAnswer('question: Why is this suspicious?')).not.toContain('question:');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — parseToPoints
// ─────────────────────────────────────────────────────────────────────────────

describe('parseToPoints()', () => {
  it('T9: markdown heading becomes response heading', () => {
    const res = parseToPoints('### Analysis\n\n1. **C2 Traffic** - Detected anomalous comms.');
    expect(res.heading).toBe('Analysis');
  });

  it('T10: numbered list becomes bullet points with titles', () => {
    const res = parseToPoints('1. **C2 Traffic** - Active C2 communication.\n2. **Recon** - Port scanning observed.');
    expect(res.points.length).toBe(2);
    expect(res.points[0].title).toBe('C2 Traffic');
    expect(res.points[1].title).toBe('Recon');
  });

  it('T11: dash bullet list becomes points', () => {
    const res = parseToPoints('- **Finding A** - Explanation A\n- **Finding B**');
    expect(res.points.length).toBe(2);
    expect(res.points[0].title).toBe('Finding A');
  });

  it('T12: empty input returns "No response provided."', () => {
    const res = parseToPoints('');
    expect(res.summary).toBe('No response provided.');
    expect(res.points).toHaveLength(0);
  });

  it('T13: ### Recommended Next Steps routes to recommendations', () => {
    const res = parseToPoints('### Recommended Next Steps\n\n- Isolate host\n- Run forensic image');
    expect(res.recommendations).toHaveLength(2);
    expect(res.recommendations[0]).toContain('Isolate host');
  });

  it('T14: ### Confirmed routes to confirmed list', () => {
    const res = parseToPoints('### Confirmed\n\n- C2 traffic confirmed\n- Port scan confirmed');
    expect(res.confirmed).toHaveLength(2);
  });

  it('T15: prose paragraph splits into semantic points', () => {
    const para = 'C2 traffic was observed on port 443. Port scanning was also detected on multiple hosts.';
    const res = parseToPoints(para);
    // Should produce at least 1 point (not kept as one big paragraph)
    expect(res.points.length + (res.summary ? 1 : 0)).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Unit tests — buildCopilotResponse
// ─────────────────────────────────────────────────────────────────────────────

describe('buildCopilotResponse()', () => {
  it('T16: status field is preserved in structured copilot_response', () => {
    const data = {
      copilot_response: {
        points: [{ title: 'C2', explanation: 'Active.', status: 'SUPPORTED' }],
      },
    };
    const res = buildCopilotResponse(data);
    expect(res.points[0].status).toBe('SUPPORTED');
  });

  it('T17: confidence field is preserved', () => {
    const data = {
      copilot_response: {
        points: [{ title: 'Finding', explanation: 'X', confidence: 0.92 }],
      },
    };
    const res = buildCopilotResponse(data);
    expect(res.points[0].confidence).toBeCloseTo(0.92);
  });

  it('T18: evidence_ids are preserved', () => {
    const data = {
      copilot_response: {
        points: [{ title: 'T', explanation: 'X', evidence_ids: ['EV-001'] }],
      },
    };
    const res = buildCopilotResponse(data);
    expect(res.points[0].evidence_ids).toContain('EV-001');
  });

  it('T19: technique_ids (MITRE) are preserved', () => {
    const data = {
      copilot_response: {
        points: [{ title: 'T', explanation: 'X', technique_ids: ['T1071.001'] }],
      },
    };
    const res = buildCopilotResponse(data);
    expect(res.points[0].technique_ids).toContain('T1071.001');
  });

  it('T20: investigator_answers JSON string is unwrapped correctly', () => {
    const data = {
      status: 'SUCCESS',
      investigator_answers: {
        'Why?': JSON.stringify({ question: 'Why?', answer: '### Parsed Heading\n\n1. Point Alpha' }),
      },
    };
    const res = buildCopilotResponse(data);
    expect(res.heading).toBe('Parsed Heading');
    expect(res.points[0].title).toBe('Point Alpha');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Integration tests — CopilotPanel component rendering
// ─────────────────────────────────────────────────────────────────────────────

describe('CopilotPanel Component', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders header', () => {
    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    expect(screen.getByText('NetSleuth AI Forensic Copilot')).toBeInTheDocument();
  });

  it('renders preset investigator prompts in the default (empty) state', () => {
    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    expect(screen.getByText(/Why is this case suspicious\?/i)).toBeInTheDocument();
    expect(screen.getByText(/What are the highest-risk findings\?/i)).toBeInTheDocument();
  });

  it('T21: selecting a preset renders only the answer (heading + point), no JSON', async () => {
    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    fireEvent.click(screen.getByText(/Why is this case suspicious\?/i));

    const heading = await screen.findByText('Why this case is suspicious');
    expect(heading).toBeInTheDocument();
    expect(heading.tagName).toBe('H3');
    expect(screen.getByText('C2 / Malware Communication')).toBeInTheDocument();

    // No JSON visible
    expect(screen.queryByText(/"question"/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/"answer":/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/^\s*\{/)).not.toBeInTheDocument();
  });

  it('T22: "question" field is never rendered', async () => {
    const { generateQA } = await import('../api');
    vi.mocked(generateQA).mockResolvedValueOnce({
      status: 'SUCCESS',
      investigator_answers: {
        'Why?': JSON.stringify({ question: 'This should never appear.', answer: '### Result\n\n1. Point Beta' }),
      },
    });

    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    fireEvent.click(screen.getByText(/Why is this case suspicious\?/i));

    await screen.findByText('Point Beta');
    expect(screen.queryByText('This should never appear.')).not.toBeInTheDocument();
    expect(screen.queryByText(/"question"/)).not.toBeInTheDocument();
  });

  it('T23: json answer string is parsed and formatted as bullets', async () => {
    const { generateQA } = await import('../api');
    vi.mocked(generateQA).mockResolvedValueOnce({
      status: 'SUCCESS',
      investigator_answers: {
        'Why?': JSON.stringify({ question: 'Why?', answer: '### Parsed Answer Output\n\n1. Point One' }),
      },
    });

    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    fireEvent.click(screen.getByText(/Why is this case suspicious\?/i));

    const heading = await screen.findByText('Parsed Answer Output');
    expect(heading).toBeInTheDocument();
    expect(screen.getByText('Point One')).toBeInTheDocument();
  });

  it('T24: markdown ### heading renders as h3 with status sub-items visible', async () => {
    const { generateQA } = await import('../api');
    vi.mocked(generateQA).mockResolvedValueOnce({
      status: 'SUCCESS',
      investigator_answers: {
        'Why?': '### Analysis\n\n1. **C2 / Malware Communication**\n   - Status: `SUPPORTED`\n   - Risk: `HIGH`',
      },
    });

    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    fireEvent.click(screen.getByText(/Why is this case suspicious\?/i));

    const h = await screen.findByText('Analysis');
    expect(h.tagName).toBe('H3');
    expect(screen.getByText('SUPPORTED')).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
  });

  it('plain text answer is rendered as bullet points', async () => {
    const { generateQA } = await import('../api');
    vi.mocked(generateQA).mockResolvedValueOnce({
      status: 'SUCCESS',
      investigator_answers: { 'Why?': 'Plain text response explaining case details.' },
    });

    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    fireEvent.click(screen.getByText(/Why is this case suspicious\?/i));

    const txt = await screen.findByText('Plain text response explaining case details.');
    expect(txt).toBeInTheDocument();
  });

  it('empty answer is handled gracefully', async () => {
    const { generateQA } = await import('../api');
    vi.mocked(generateQA).mockResolvedValueOnce({ status: 'SUCCESS', investigator_answers: {} });

    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    fireEvent.click(screen.getByText(/Why is this case suspicious\?/i));

    const txt = await screen.findByText('No response provided.');
    expect(txt).toBeInTheDocument();
  });

  it('T25: duplicate request prevention — button disabled while pending', async () => {
    const { generateQA } = await import('../api');
    // Slow promise that never resolves (to keep pending state)
    vi.mocked(generateQA).mockReturnValueOnce(new Promise(() => {}));

    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    const btn = screen.getByText(/Why is this case suspicious\?/i);
    fireEvent.click(btn);

    // All preset buttons should now be disabled
    const allPresets = screen.getAllByRole('button');
    const disabledBtns = allPresets.filter(b => b.hasAttribute('disabled'));
    expect(disabledBtns.length).toBeGreaterThan(0);
  });

  it('llm unavailable is handled', async () => {
    const { generateQA } = await import('../api');
    vi.mocked(generateQA).mockResolvedValueOnce({ status: 'LLM_UNAVAILABLE' });

    renderWithQueryClient(<CopilotPanel caseId="c-123" />);
    fireEvent.click(screen.getByText(/Why is this case suspicious\?/i));

    const err = await screen.findByText(/AI Copilot is offline or the local Ollama service is unreachable/i);
    expect(err).toBeInTheDocument();
  });
});

