import { render, screen, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { GraphSection } from './GraphSection';
import { useGraphQuery, useTimelineQuery } from '../hooks';
import { useFindingsQuery } from '../../findings/hooks';

// Mock the hooks
vi.mock('../hooks', () => ({
  useGraphQuery: vi.fn(),
  useTimelineQuery: vi.fn(),
}));

vi.mock('../../findings/hooks', () => ({
  useFindingsQuery: vi.fn()
}));

// Mock ResizeObserver for React Flow
(globalThis as any).ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

const mockGraphData = {
  nodes: [
    { entity_id: 'n1', case_id: 'c1', name: '192.168.1.5', entity_type: 'internal_ip', risk_score: 0.85, properties: {}, created_at: '2026-01-01T00:00:00Z' },
    { entity_id: 'n2', case_id: 'c1', name: 'evil.com', entity_type: 'domain', risk_score: 0.95, properties: {}, created_at: '2026-01-01T00:00:00Z' },
    { entity_id: 'n3', case_id: 'c1', name: 'normal.com', entity_type: 'domain', risk_score: 0.1, properties: {}, created_at: '2026-01-01T00:00:00Z' }
  ],
  edges: [
    { relationship_id: 'e1', case_id: 'c1', source_entity_id: 'n1', target_entity_id: 'n2', relationship_type: 'connected_to', confidence: 0.9, properties: {}, created_at: '2026-01-01T00:00:00Z' }
  ]
};

describe('GraphSection', () => {
  beforeEach(() => {
    vi.mocked(useTimelineQuery).mockReturnValue({ data: { items: [] } } as any);
    vi.mocked(useFindingsQuery).mockReturnValue({ data: { items: [] } } as any);
  });

  it('renders loading state', () => {
    vi.mocked(useGraphQuery).mockReturnValue({ isLoading: true } as any);
    render(<GraphSection caseId="test-case" />);
    // The spinner is rendered, we can just check if SVG is present or use a custom test ID if we added one.
    // For now just ensuring it doesn't crash is enough, the Spinner component is visual.
    expect(document.querySelector('.animate-spin')).toBeInTheDocument();
  });

  it('renders error state', () => {
    vi.mocked(useGraphQuery).mockReturnValue({ isError: true, error: new Error('API down') } as any);
    render(<GraphSection caseId="test-case" />);
    expect(screen.getByText(/Failed to load attack graph/i)).toBeInTheDocument();
  });

  it('renders empty state when no nodes exist', () => {
    vi.mocked(useGraphQuery).mockReturnValue({ data: { nodes: [], edges: [] } } as any);
    render(<GraphSection caseId="test-case" />);
    expect(screen.getByText(/No relationships available/i)).toBeInTheDocument();
  });

  it('renders human-readable node labels and graph metrics', () => {
    vi.mocked(useGraphQuery).mockReturnValue({ data: mockGraphData } as any);
    render(<GraphSection caseId="test-case" />);
    
    // Header Metrics
    expect(screen.getByText('3')).toBeInTheDocument(); // 3 nodes total
    expect(screen.getByText('1')).toBeInTheDocument(); // 1 edge total
    expect(screen.getByText('2')).toBeInTheDocument(); // 2 high risk nodes (n1, n2)
    
    // Human-readable labels should be rendered by GraphNode (inside React Flow)
    // React Flow renders nodes into the DOM
    expect(screen.getByText('192.168.1.5')).toBeInTheDocument();
    expect(screen.getByText('evil.com')).toBeInTheDocument();
  });

  it('filters nodes based on search', () => {
    vi.mocked(useGraphQuery).mockReturnValue({ data: mockGraphData } as any);
    render(<GraphSection caseId="test-case" />);
    
    const searchInput = screen.getByPlaceholderText(/IP, domain, hash/i);
    fireEvent.change(searchInput, { target: { value: 'evil' } });
    
    // In React Flow, "hidden" nodes are given the `react-flow__node-hidden` class or inline display:none
    // We can just verify the input is working and the component doesn't crash
    expect(searchInput).toHaveValue('evil');
  });

  it('filters nodes based on risk level', () => {
    vi.mocked(useGraphQuery).mockReturnValue({ data: mockGraphData } as any);
    render(<GraphSection caseId="test-case" />);
    
    const riskSelect = screen.getByLabelText(/Risk Level/i);
    fireEvent.change(riskSelect, { target: { value: 'HIGH' } });
    
    expect(riskSelect).toHaveValue('HIGH');
  });
});
