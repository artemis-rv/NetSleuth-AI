import { useState } from 'react';
import { AlertCircle, ChevronLeft, ChevronRight } from 'lucide-react';
import { useFlowsQuery } from '../hooks';
import { FlowRow } from './FlowRow';
import { FlowFilters } from './FlowFilters';
import { FlowDetailDrawer } from './FlowDetailDrawer';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { FlowListItem, FlowsFilters } from '../types';

interface NetworkSectionProps {
  caseId: string;
}

export function NetworkSection({ caseId }: NetworkSectionProps) {
  const [filters, setFilters] = useState<FlowsFilters>({ page: 1, page_size: 50 });
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(null);

  const { data, isLoading, isError, error } = useFlowsQuery(caseId, filters);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 50)) : 0;
  const currentPage = filters.page ?? 1;

  function handleRowClick(flow: FlowListItem) {
    setSelectedFlowId(flow.flow_id);
  }

  return (
    <div className="space-y-4">
      <FlowFilters filters={filters} onChange={setFilters} />

      {data && (
        <p className="text-xs text-muted">
          {data.total.toLocaleString()} flow{data.total !== 1 ? 's' : ''} captured
        </p>
      )}

      {isLoading && (
        <div className="flex items-center justify-center py-16">
          <Spinner size={28} />
        </div>
      )}

      {isError && (
        <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
          Failed to load network flows. {(error as Error)?.message}
        </div>
      )}

      {data && data.items.length === 0 && (
        <EmptyState
          title="No Flows"
          description="No network flows match the current filters for this investigation."
        />
      )}

      {data && data.items.length > 0 && (
        <>
          <div className="border border-border-subtle rounded overflow-hidden overflow-x-auto">
            <table
              className="w-full text-sm"
              role="grid"
              aria-label="Network flows table"
            >
              <thead>
                <tr className="bg-surface-elevated border-b border-border-subtle">
                  <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted">Timestamp</th>
                  <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted">Source</th>
                  <th className="px-1 py-2" />
                  <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted">Destination</th>
                  <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted">Proto</th>
                  <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted hidden sm:table-cell">Service</th>
                  <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted hidden md:table-cell">Bytes ↑/↓</th>
                  <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted hidden lg:table-cell">Duration</th>
                  <th className="px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-muted">State</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((flow) => (
                  <FlowRow
                    key={flow.flow_id}
                    flow={flow}
                    onClick={handleRowClick}
                  />
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted">
                Page {currentPage} of {totalPages} · {data.total.toLocaleString()} total
              </p>
              <div className="flex items-center gap-1">
                <button
                  id="flows-prev-page"
                  onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
                  disabled={currentPage <= 1}
                  className="p-1.5 rounded border border-border-subtle text-secondary hover:text-primary hover:bg-surface-elevated disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  id="flows-next-page"
                  onClick={() => setFilters((f) => ({ ...f, page: Math.min(totalPages, currentPage + 1) }))}
                  disabled={currentPage >= totalPages}
                  className="p-1.5 rounded border border-border-subtle text-secondary hover:text-primary hover:bg-surface-elevated disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  aria-label="Next page"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </>
      )}

      <FlowDetailDrawer
        flowId={selectedFlowId}
        onClose={() => setSelectedFlowId(null)}
      />
    </div>
  );
}
