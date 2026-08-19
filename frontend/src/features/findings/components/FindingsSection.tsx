

import { useState } from 'react';
import { AlertCircle, ChevronLeft, ChevronRight } from 'lucide-react';
import { useFindingsQuery } from '../hooks';
import { FindingRow } from './FindingRow';
import { FindingFilters } from './FindingFilters';
import { FindingDetailDrawer } from './FindingDetailDrawer';
import { Spinner } from '../../../components/ui/Spinner';
import type { FindingListItem, FindingsFilters } from '../types';

interface FindingsSectionProps {
  caseId: string;
}

export function FindingsSection({ caseId }: FindingsSectionProps) {
  const [filters, setFilters] = useState<FindingsFilters>({ page: 1, page_size: 25 });
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const { data, isLoading, isError, error } = useFindingsQuery(caseId, filters);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 25)) : 0;
  const currentPage = filters.page ?? 1;

  function handleRowClick(finding: FindingListItem) {
    setSelectedFindingId(finding.finding_id);
  }

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <FindingFilters filters={filters} onChange={setFilters} />

      {/* Summary line */}
      {data && (
        <div className="flex items-center gap-3 text-[11px] font-mono tracking-widest text-muted">
          <span className="bg-surface-elevated/50 px-2.5 py-1 rounded border border-border-subtle shadow-sm uppercase font-semibold">
            {data.total.toLocaleString()} TOTAL FINDINGS
          </span>
          <span className="bg-surface-elevated/50 px-2.5 py-1 rounded border border-border-subtle shadow-sm uppercase font-semibold">
            SHOWING {data.items.length}
          </span>
          {Object.keys(filters).some(k => k !== 'page' && k !== 'page_size' && filters[k as keyof typeof filters] !== undefined) && (
            <span className="bg-accent/10 text-accent px-2.5 py-1 rounded border border-accent/20 shadow-sm uppercase font-semibold">
              FILTERED
            </span>
          )}
        </div>
      )}

      {/* Loading */}
      {isLoading && (
        <div className="flex items-center justify-center py-16">
          <Spinner size={28} />
        </div>
      )}

      {/* Error */}
      {isError && (
        <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
          Failed to load findings. {(error as Error)?.message}
        </div>
      )}

      {/* Results */}
      {data && data.items.length === 0 && (
        <div className="flex items-center justify-between p-4 rounded-md border border-border-subtle bg-surface-elevated/30">
          <p className="text-[13px] text-secondary">No findings match the current filters.</p>
          {Object.keys(filters).some(k => k !== 'page' && k !== 'page_size' && filters[k as keyof typeof filters] !== undefined) && (
            <button 
              onClick={() => setFilters({ page: 1, page_size: filters.page_size })}
              className="text-xs text-accent hover:underline px-3 py-1 rounded border border-border-subtle bg-surface hover:bg-surface-elevated transition-colors"
            >
              Clear filters
            </button>
          )}
        </div>
      )}

      {data && data.items.length > 0 && (
        <>
          <div className="border border-border-subtle rounded-md overflow-hidden bg-surface/30">
            <table
              className="w-full text-sm"
              role="grid"
              aria-label="Findings table"
            >
              <thead>
                <tr className="bg-surface-elevated/80 border-b border-border-subtle text-[11px] uppercase tracking-wider text-muted font-bold">
                  <th className="px-4 py-3 text-left font-semibold">Severity</th>
                  <th className="px-4 py-3 text-left font-semibold">Activity</th>
                  <th className="px-4 py-3 text-left font-semibold">Risk</th>
                  <th className="px-4 py-3 text-left font-semibold">Decision</th>
                  <th className="px-4 py-3 text-left font-semibold hidden md:table-cell">Method</th>
                  <th className="px-4 py-3 text-right font-semibold">Detected</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((finding) => (
                  <FindingRow
                    key={finding.finding_id}
                    finding={finding}
                    onClick={handleRowClick}
                  />
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2">
              <p className="text-[12px] text-muted">
                Showing {((currentPage - 1) * (filters.page_size ?? 25)) + 1}–{Math.min(currentPage * (filters.page_size ?? 25), data.total)} of {data.total.toLocaleString()}
              </p>
              <div className="flex items-center gap-1.5">
                <button
                  id="findings-prev-page"
                  onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
                  disabled={currentPage <= 1}
                  className="flex items-center gap-1 px-2.5 py-1.5 text-[12px] rounded border border-border-subtle text-secondary hover:text-primary hover:bg-surface-elevated disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-3.5 w-3.5" /> Previous
                </button>
                <div className="flex items-center gap-1 px-2">
                  {Array.from({ length: Math.min(5, totalPages) }, (_, i) => {
                    let p = currentPage - 2 + i;
                    if (currentPage <= 3) p = i + 1;
                    else if (currentPage >= totalPages - 2) p = totalPages - 4 + i;
                    if (p < 1 || p > totalPages) return null;
                    return (
                      <button
                        key={p}
                        onClick={() => setFilters((f) => ({ ...f, page: p }))}
                        className={`w-7 h-7 flex items-center justify-center rounded text-[12px] transition-colors ${
                          p === currentPage
                            ? 'bg-surface-elevated border border-border-subtle text-primary font-bold shadow-sm'
                            : 'text-muted hover:text-primary hover:bg-surface/50'
                        }`}
                      >
                        {p}
                      </button>
                    );
                  })}
                </div>
                <button
                  id="findings-next-page"
                  onClick={() => setFilters((f) => ({ ...f, page: Math.min(totalPages, currentPage + 1) }))}
                  disabled={currentPage >= totalPages}
                  className="flex items-center gap-1 px-2.5 py-1.5 text-[12px] rounded border border-border-subtle text-secondary hover:text-primary hover:bg-surface-elevated disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  aria-label="Next page"
                >
                  Next <ChevronRight className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}
        </>
      )}

      {/* Detail drawer */}
      <FindingDetailDrawer
        findingId={selectedFindingId}
        onClose={() => setSelectedFindingId(null)}
      />
    </div>
  );
}
