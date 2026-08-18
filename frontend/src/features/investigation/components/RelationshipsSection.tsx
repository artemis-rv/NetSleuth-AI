import { useState } from 'react';
import { AlertCircle, ArrowRight, ChevronLeft, ChevronRight } from 'lucide-react';
import { useRelationshipsQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { PaginationFilters } from '../types';

function ConfidenceChip({ value }: { value: number | null }) {
  if (value === null) return null;
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? 'text-green-400 bg-green-500/10' : pct >= 50 ? 'text-yellow-400 bg-yellow-500/10' : 'text-slate-400 bg-slate-500/10';
  return (
    <span className={`text-[10px] font-medium rounded px-1.5 py-0.5 tabular-nums ${color}`}>
      {pct}% conf
    </span>
  );
}

interface RelationshipsSectionProps {
  caseId: string;
}

export function RelationshipsSection({ caseId }: RelationshipsSectionProps) {
  const [filters, setFilters] = useState<PaginationFilters>({ page: 1, page_size: 50 });
  const { data, isLoading, isError, error } = useRelationshipsQuery(caseId, filters);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 50)) : 0;
  const currentPage = filters.page ?? 1;

  return (
    <div className="space-y-4">
      {data && (
        <p className="text-xs text-muted">
          {data.total.toLocaleString()} relationship{data.total !== 1 ? 's' : ''} mapped
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
          Failed to load relationships. {(error as Error)?.message}
        </div>
      )}

      {data && data.items.length === 0 && (
        <EmptyState title="No Relationships" description="No entity relationships have been mapped for this investigation." />
      )}

      {data && data.items.length > 0 && (
        <>
          <div className="border border-border-subtle rounded overflow-hidden">
            <table className="w-full text-sm" role="grid" aria-label="Relationships table">
              <thead>
                <tr className="bg-surface-elevated border-b border-border-subtle">
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Source Entity</th>
                  <th className="px-2 py-2.5 text-center text-xs font-semibold uppercase tracking-wide text-muted">Relationship</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Target Entity</th>
                  <th className="px-4 py-2.5 text-right text-xs font-semibold uppercase tracking-wide text-muted">Confidence</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((rel) => (
                  <tr
                    key={rel.relationship_id}
                    className="border-b border-border-subtle hover:bg-surface-elevated/40 transition-colors"
                  >
                    <td className="px-4 py-2.5">
                      <span className="text-xs text-primary font-mono truncate block max-w-[160px]" title={rel.source_entity_id}>
                        {rel.source_entity_id.slice(0, 8)}…
                      </span>
                    </td>
                    <td className="px-2 py-2.5 text-center">
                      <div className="flex items-center justify-center gap-1">
                        <span className="text-xs text-accent font-medium">
                          {rel.relationship_type.replace(/_/g, ' ')}
                        </span>
                        <ArrowRight className="h-3 w-3 text-muted flex-shrink-0" aria-hidden="true" />
                      </div>
                    </td>
                    <td className="px-4 py-2.5">
                      <span className="text-xs text-primary font-mono truncate block max-w-[160px]" title={rel.target_entity_id}>
                        {rel.target_entity_id.slice(0, 8)}…
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <ConfidenceChip value={rel.confidence} />
                    </td>
                  </tr>
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
                  id="relationships-prev-page"
                  onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
                  disabled={currentPage <= 1}
                  className="p-1.5 rounded border border-border-subtle text-secondary hover:text-primary hover:bg-surface-elevated disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  id="relationships-next-page"
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
    </div>
  );
}
