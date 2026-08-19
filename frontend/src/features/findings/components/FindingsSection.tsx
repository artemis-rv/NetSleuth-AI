import { useState } from 'react';
import { AlertCircle, ChevronLeft, ChevronRight } from 'lucide-react';
import { useFindingsQuery } from '../hooks';
import { useAnalysisJobs } from '../../analysis/hooks';
import { FindingRow } from './FindingRow';
import { FindingFilters } from './FindingFilters';
import { FindingDetailDrawer } from './FindingDetailDrawer';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { FindingListItem, FindingsFilters } from '../types';

interface FindingsSectionProps {
  caseId: string;
}

export function FindingsSection({ caseId }: FindingsSectionProps) {
  const [filters, setFilters] = useState<FindingsFilters>({ page: 1, page_size: 25 });
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);

  const { data, isLoading, isError, error } = useFindingsQuery(caseId, filters);
  const { data: analysisData } = useAnalysisJobs(caseId);

  const hasJobs = (analysisData?.jobs?.length ?? 0) > 0;

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
        <p className="text-xs text-muted">
          {data.total.toLocaleString()} finding{data.total !== 1 ? 's' : ''} found
        </p>
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
        <EmptyState
          title={!hasJobs ? "Analysis Not Started" : "No Findings Detected"}
          description={
            !hasJobs
              ? "Forensic analysis has not been executed for this case yet. Please navigate to the Overview tab and click Start Analysis."
              : "The analysis pipeline completed and detected zero security findings for this acquisition."
          }
        />
      )}

      {data && data.items.length > 0 && (
        <>
          <div className="border border-border-subtle rounded overflow-hidden">
            <table
              className="w-full text-sm"
              role="grid"
              aria-label="Findings table"
            >
              <thead>
                <tr className="bg-surface-elevated border-b border-border-subtle">
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Severity</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Activity</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Risk</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Decision</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted hidden md:table-cell">Method</th>
                  <th className="px-4 py-2.5 text-right text-xs font-semibold uppercase tracking-wide text-muted">Detected</th>
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
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted">
                Page {currentPage} of {totalPages} · {data.total.toLocaleString()} total
              </p>
              <div className="flex items-center gap-1">
                <button
                  id="findings-prev-page"
                  onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
                  disabled={currentPage <= 1}
                  className="p-1.5 rounded border border-border-subtle text-secondary hover:text-primary hover:bg-surface-elevated disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  id="findings-next-page"
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

      {/* Detail drawer */}
      <FindingDetailDrawer
        findingId={selectedFindingId}
        onClose={() => setSelectedFindingId(null)}
      />
    </div>
  );
}
