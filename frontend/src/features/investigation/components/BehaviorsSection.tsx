import { useState } from 'react';
import { AlertCircle, ChevronLeft, ChevronRight } from 'lucide-react';
import { useBehaviorsQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { PaginationFilters } from '../types';

const SEVERITY_STYLES: Record<string, string> = {
  undefined: 'border-slate-500/40 bg-slate-500/10 text-slate-400',
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
};

function formatDateRange(start: string | null | undefined, end: string | null | undefined): string {
  if (!start && !end) return 'Observation window pending';
  if (!start) return `Until ${new Date(end!).toLocaleDateString()}`;
  if (!end) return `Since ${new Date(start).toLocaleDateString()}`;
  const s = new Date(start);
  const e = new Date(end);
  const diff = Math.round((e.getTime() - s.getTime()) / 1000);
  let span: string;
  if (diff < 60) span = `${diff}s`;
  else if (diff < 3600) span = `${Math.round(diff / 60)}m`;
  else if (diff < 86400) span = `${Math.round(diff / 3600)}h`;
  else span = `${Math.round(diff / 86400)}d`;
  return `${s.toLocaleDateString()} (${span} span)`;
}

interface BehaviorsSectionProps {
  caseId: string;
}

export function BehaviorsSection({ caseId }: BehaviorsSectionProps) {
  const [filters, setFilters] = useState<PaginationFilters>({ page: 1, page_size: 50 });
  const { data, isLoading, isError, error } = useBehaviorsQuery(caseId, filters);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 50)) : 0;
  const currentPage = filters.page ?? 1;

  return (
    <div className="space-y-4">
      {data && (
        <p className="text-xs text-muted">
          {data.total.toLocaleString()} behavior{data.total !== 1 ? 's' : ''} identified
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
          Failed to load behaviors. {(error as Error)?.message}
        </div>
      )}

      {data && data.items.length === 0 && (
        <EmptyState title="No Behaviors" description="No anomalous behaviors have been identified for this investigation." />
      )}

      {data && data.items.length > 0 && (
        <>
          <div className="space-y-2">
            {data.items.map((beh) => {
              const sevStyle = beh.severity ? SEVERITY_STYLES[beh.severity.toLowerCase()] ?? SEVERITY_STYLES.unknown : SEVERITY_STYLES.unknown;
              const confidence = beh.confidence !== null ? `${Math.round(beh.confidence * 100)}%` : null;

              return (
                <div
                  key={beh.behavior_id}
                  className="border border-border-subtle rounded p-3.5 space-y-2 hover:bg-surface-elevated/30 transition-colors"
                >
                  {/* Header */}
                  <div className="flex items-start gap-2.5">
                    <span className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-semibold uppercase flex-shrink-0 ${sevStyle}`}>
                      {beh.severity}
                    </span>
                    <div className="flex items-center gap-2 mb-1">
                      <p className="text-sm font-medium text-primary">{beh.label}</p>
                      <p className="text-xs text-muted">{beh.behavior_type?.replace(/_/g, ' ')}</p>
                    </div>
                    {confidence && (
                      <span className="text-xs text-secondary bg-surface-elevated border border-border-subtle rounded px-1.5 py-0.5 flex-shrink-0">
                        {confidence} conf
                      </span>
                    )}
                  </div>

                  {/* Description */}
                  {beh.description && (
                    <p className="text-xs text-secondary leading-relaxed pl-0.5">
                      {beh.description}
                    </p>
                  )}

                  {/* Observation window */}
                  <p className="text-xs text-muted">
                    Observed: {formatDateRange(beh.first_observed, beh.last_observed)}
                  </p>
                </div>
              );
            })}
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted">
                Page {currentPage} of {totalPages} · {data.total.toLocaleString()} total
              </p>
              <div className="flex items-center gap-1">
                <button
                  id="behaviors-prev-page"
                  onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
                  disabled={currentPage <= 1}
                  className="p-1.5 rounded border border-border-subtle text-secondary hover:text-primary hover:bg-surface-elevated disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  id="behaviors-next-page"
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
