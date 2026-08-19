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
          {/* Premium Timeline Feed */}
          <div className="relative pl-10 pt-2 space-y-6">
            {/* Glowing Vertical Line */}
            <div 
              className="absolute left-5 top-4 bottom-0 w-px bg-gradient-to-b from-accent/60 via-border-subtle to-transparent shadow-[0_0_8px_rgba(59,130,246,0.4)]" 
              aria-hidden="true" 
            />

            {data.items.map((evt) => {
              const typeStyle = EVENT_TYPE_STYLES[evt.event_type?.toLowerCase()] ?? 'bg-slate-500/15 text-slate-400 border-slate-500/20';
              return (
                <div
                  key={evt.timeline_event_id}
                  className="relative group"
                  role="listitem"
                >
                  {/* Pulsating Glow Node */}
                  <div className="absolute -left-5 top-3.5 -translate-x-1/2 flex h-4 w-4 items-center justify-center">
                    <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent/40 opacity-75 group-hover:bg-accent/80 transition-colors duration-500"></span>
                    <span className="relative inline-flex h-2.5 w-2.5 rounded-full bg-accent ring-[5px] ring-background shadow-[0_0_12px_rgba(59,130,246,0.9)] group-hover:scale-125 transition-transform duration-300"></span>
                  </div>

                  {/* Glassmorphic Event Card */}
                  <div className="relative overflow-hidden rounded-xl border border-border-subtle bg-surface/30 p-4 transition-all duration-300 hover:bg-surface-elevated/80 hover:border-accent/40 hover:shadow-xl hover:shadow-accent/10 backdrop-blur-sm group-hover:-translate-y-0.5">
                    {/* Hover indicator bar */}
                    <div className="absolute left-0 top-0 bottom-0 w-[3px] bg-gradient-to-b from-accent to-accent/10 opacity-0 group-hover:opacity-100 transition-opacity duration-300" />
                    
                    {/* Header row */}
                    <div className="flex items-center gap-3 flex-wrap mb-2">
                      <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider border ${typeStyle}`}>
                        {evt.event_type.replace(/_/g, ' ')}
                      </span>
                      <span className="flex items-center gap-1.5 text-xs text-muted font-mono bg-background/50 px-2 py-0.5 rounded-md border border-border-subtle/50">
                        <Clock className="h-3 w-3 text-accent/70" aria-hidden="true" />
                        {new Date(evt.event_timestamp).toLocaleString('en-US', {
                          month: 'short', day: '2-digit',
                          hour: '2-digit', minute: '2-digit', second: '2-digit',
                          hour12: false,
                        })}
                      </span>
                    </div>

                    {/* Description */}
                    {evt.description && (
                      <p className="text-sm text-primary/90 leading-relaxed font-medium">{evt.description}</p>
                    )}

                    {/* Source ref */}
                    {evt.source_id && (
                      <div className="mt-3 pt-3 border-t border-border-subtle/40 flex items-center gap-2">
                        <span className="text-[10px] text-muted font-medium uppercase tracking-wider">Source:</span>
                        <code className="text-[11px] text-muted font-mono bg-background/50 px-1.5 py-0.5 rounded border border-border-subtle/30">
                          {evt.source_id}
                        </code>
                      </div>
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
