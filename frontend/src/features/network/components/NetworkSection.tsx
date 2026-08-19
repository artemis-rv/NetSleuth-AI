import { useState } from 'react';
import { AlertCircle, ChevronRight, ChevronLeft } from 'lucide-react';
import { useEndpointContextsQuery } from '../hooks';
import { EndpointFilters } from './EndpointFilters';
import { EndpointContextRow } from './EndpointContextRow';
import { EndpointDetailDrawer } from './EndpointDetailDrawer'; // Updated import
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { FlowsFilters } from '../types';

interface NetworkSectionProps {
  caseId: string;
}

export function NetworkSection({ caseId }: NetworkSectionProps) {
  const [filters, setFilters] = useState<FlowsFilters>({ page: 1, page_size: 50, sort_by: 'risk_score' });
  const [selectedEndpointIp, setSelectedEndpointIp] = useState<string | null>(null);

  const { data, isLoading, isError, error } = useEndpointContextsQuery(caseId, filters);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 50)) : 0;
  const currentPage = filters.page ?? 1;

  function handleSelectEndpoint(ip: string) {
    setSelectedEndpointIp(ip);
  }

  function handleSelectFinding(_findingId: string) {
    // Finding click navigation if needed
  }

  return (
    <div className="space-y-4">
      {/* Header Context Controls & Filters */}
      <EndpointFilters filters={filters} onChange={setFilters} />

      {data && (
        <div className="flex items-center justify-between text-xs text-muted font-mono">
          <span>{data.total.toLocaleString()} endpoint context{data.total !== 1 ? 's' : ''} aggregated from capture</span>
          <div className="flex items-center gap-3 font-mono">
            <span className="text-emerald-400 font-medium">{data.internal_count} Internal / Private</span>
            <span className="text-amber-400 font-medium">{data.external_count} External / Public</span>
          </div>
        </div>
      )}

      {isLoading && (
        <div className="flex items-center justify-center py-16">
          <Spinner size={28} />
        </div>
      )}

      {isError && (
        <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
          Failed to load network endpoint context. {(error as Error)?.message}
        </div>
      )}

      {data && data.items.length === 0 && (
        <EmptyState
          title="No Endpoints Found"
          description="No network endpoint contexts match the current filters for this investigation."
        />
      )}

      {data && data.items.length > 0 && (
        <div className="space-y-3">
          {data.items.map((endpoint) => (
            <EndpointContextRow
              key={endpoint.ip}
              endpoint={endpoint}
              onSelectFlow={handleSelectEndpoint}
              onSelectFinding={handleSelectFinding}
            />
          ))}
        </div>
      )}

      {/* Pagination Controls */}
      {data && data.items.length > 0 && totalPages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <p className="text-xs text-muted font-mono">
            Page {currentPage} of {totalPages} · {data.total.toLocaleString()} total endpoints
          </p>
          <div className="flex items-center gap-1">
            <button
              id="endpoint-prev-page"
              onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
              disabled={currentPage <= 1}
              className="p-1 text-muted hover:text-primary disabled:opacity-30 transition-colors rounded hover:bg-surface-elevated"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              id="endpoint-next-page"
              onClick={() => setFilters((f) => ({ ...f, page: Math.min(totalPages, currentPage + 1) }))}
              disabled={currentPage >= totalPages}
              className="p-1 text-muted hover:text-primary disabled:opacity-30 transition-colors rounded hover:bg-surface-elevated"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {/* Endpoint Detail Drawer */}
      {selectedEndpointIp && (
        <EndpointDetailDrawer
          caseId={caseId}
          endpointIp={selectedEndpointIp}
          onClose={() => setSelectedEndpointIp(null)}
        />
      )}
    </div>
  );
}
