import { useState } from 'react';
import { AlertCircle, ChevronLeft, ChevronRight, Clock } from 'lucide-react';
import { useTimelineQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { PaginationFilters } from '../types';

const EVENT_TYPE_STYLES: Record<string, string> = {
  network_flow: 'bg-blue-500/15 text-blue-400',
  finding: 'bg-red-500/15 text-red-400',
  behavior: 'bg-orange-500/15 text-orange-400',
  entity: 'bg-purple-500/15 text-purple-400',
  acquisition: 'bg-teal-500/15 text-teal-400',
  analysis: 'bg-green-500/15 text-green-400',
};

interface TimelineSectionProps {
  caseId: string;
}

export function TimelineSection({ caseId }: TimelineSectionProps) {
  const [filters, setFilters] = useState<PaginationFilters>({ page: 1, page_size: 50 });
  const { data, isLoading, isError, error } = useTimelineQuery(caseId, filters);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 50)) : 0;
  const currentPage = filters.page ?? 1;

  return (
    <div className="space-y-4">
      {data && (
        <p className="text-xs text-muted">
          {data.total.toLocaleString()} event{data.total !== 1 ? 's' : ''} in timeline
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
          Failed to load timeline. {(error as Error)?.message}
        </div>
      )}

      {data && data.items.length === 0 && (
        <EmptyState
          title="No Timeline Events"
          description="No events have been recorded in the timeline for this investigation yet."
        />
      )}

      {data && data.items.length > 0 && (
        <>
          {/* Timeline feed */}
          <div className="relative pl-6 space-y-0">
            {/* Vertical line */}
            <div className="absolute left-2.5 top-0 bottom-0 w-px bg-border-subtle" aria-hidden="true" />

            {data.items.map((evt) => {
              const typeStyle = EVENT_TYPE_STYLES[evt.event_type?.toLowerCase()] ?? 'bg-slate-500/15 text-slate-400';
              return (
                <div
                  key={evt.timeline_event_id}
                  className="relative pb-4 last:pb-0"
                  role="listitem"
                >
                  {/* Dot */}
                  <div
                    className="absolute -left-6 top-1 h-2 w-2 rounded-full border-2 border-accent bg-surface"
                    aria-hidden="true"
                  />

                  <div className="border border-border-subtle rounded p-3 space-y-1.5 hover:bg-surface-elevated/40 transition-colors">
                    {/* Header row */}
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${typeStyle}`}>
                        {evt.event_type.replace(/_/g, ' ')}
                      </span>
                      <span className="flex items-center gap-1 text-xs text-muted tabular-nums">
                        <Clock className="h-3 w-3" aria-hidden="true" />
                        {new Date(evt.event_timestamp).toLocaleString('en-US', {
                          month: 'short', day: '2-digit',
                          hour: '2-digit', minute: '2-digit', second: '2-digit',
                          hour12: false,
                        })}
                      </span>
                    </div>

                    {/* Description */}
                    {evt.description && (
                      <p className="text-sm text-primary leading-relaxed">{evt.description}</p>
                    )}

                    {/* Source ref */}
                    {evt.source_id && (
                      <p className="text-xs text-muted font-mono">
                        src: {evt.source_id}
                      </p>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-2">
              <p className="text-xs text-muted">
                Page {currentPage} of {totalPages} · {data.total.toLocaleString()} total
              </p>
              <div className="flex items-center gap-1">
                <button
                  id="timeline-prev-page"
                  onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
                  disabled={currentPage <= 1}
                  className="p-1.5 rounded border border-border-subtle text-secondary hover:text-primary hover:bg-surface-elevated disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  id="timeline-next-page"
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
