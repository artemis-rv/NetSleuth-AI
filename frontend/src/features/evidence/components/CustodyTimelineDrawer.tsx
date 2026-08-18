import { X, Lock, Clock, User, FileText } from 'lucide-react';
import { useCustodyEventsQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { EvidenceItemResponse } from '../types';

interface CustodyTimelineDrawerProps {
  item: EvidenceItemResponse | null;
  onClose: () => void;
}

export function CustodyTimelineDrawer({ item, onClose }: CustodyTimelineDrawerProps) {
  const { data, isLoading } = useCustodyEventsQuery(item?.evidence_item_id ?? null);

  if (!item) return null;

  return (
    <>
      <div className="fixed inset-0 bg-black/40 z-40 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
      <aside
        className="fixed right-0 top-0 h-full w-full max-w-lg bg-surface border-l border-border-subtle z-50 overflow-y-auto shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-label="Chain of Custody"
      >
        {/* Header */}
        <div className="sticky top-0 bg-surface border-b border-border-subtle px-6 py-4 flex items-center justify-between z-10">
          <div className="flex items-center gap-2">
            <Lock className="h-4 w-4 text-accent" aria-hidden="true" />
            <h2 className="text-sm font-semibold text-primary">Chain of Custody Ledger</h2>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 hover:bg-surface-elevated text-muted hover:text-primary transition-colors"
            aria-label="Close chain of custody"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-6">
          {/* Item details */}
          <div className="bg-surface-elevated/40 p-4 rounded border border-border-subtle space-y-2 text-xs">
            <div className="flex justify-between">
              <span className="text-muted">Item Label:</span>
              <span className="text-primary font-medium">{item.label}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted">Type:</span>
              <span className="text-secondary font-mono">{item.evidence_type}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted">Item ID:</span>
              <span className="text-primary font-mono">{item.evidence_item_id}</span>
            </div>
            {item.sha256 && (
              <div className="flex justify-between">
                <span className="text-muted">SHA-256:</span>
                <span className="text-primary font-mono truncate max-w-[200px]" title={item.sha256}>
                  {item.sha256}
                </span>
              </div>
            )}
          </div>

          {/* Immutable notice */}
          <div className="flex items-center gap-2 p-2.5 rounded bg-surface-elevated border border-border-subtle text-[11px] text-muted">
            <Lock className="h-3.5 w-3.5 text-accent flex-shrink-0" />
            <span>Chain of custody records are immutable and tamper-evident.</span>
          </div>

          {isLoading && (
            <div className="flex items-center justify-center py-12">
              <Spinner size={24} />
            </div>
          )}

          {data && data.items.length === 0 && (
            <EmptyState
              title="No Custody Events"
              description="No custody transfer or verification events recorded for this item."
            />
          )}

          {data && data.items.length > 0 && (
            <div className="relative pl-6 space-y-0">
              <div className="absolute left-2.5 top-0 bottom-0 w-px bg-border-subtle" aria-hidden="true" />
              {data.items.map((evt) => (
                <div key={evt.custody_event_id} className="relative pb-5 last:pb-0">
                  <div className="absolute -left-6 top-1 h-2 w-2 rounded-full border-2 border-accent bg-surface" />
                  <div className="border border-border-subtle rounded p-3 space-y-1.5 hover:bg-surface-elevated/40 transition-colors">
                    <div className="flex items-center justify-between">
                      <span className="text-xs font-semibold text-accent uppercase tracking-wide">
                        {evt.action.replace(/_/g, ' ')}
                      </span>
                      <span className="flex items-center gap-1 text-[11px] text-muted tabular-nums">
                        <Clock className="h-3 w-3" />
                        {new Date(evt.occurred_at).toLocaleString()}
                      </span>
                    </div>

                    {evt.actor_name && (
                      <div className="flex items-center gap-1 text-xs text-secondary">
                        <User className="h-3 w-3 text-muted" />
                        <span>Actor: {evt.actor_name}</span>
                      </div>
                    )}

                    {evt.notes && (
                      <div className="flex items-start gap-1 text-xs text-primary pt-1">
                        <FileText className="h-3 w-3 text-muted mt-0.5" />
                        <span>{evt.notes}</span>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </aside>
    </>
  );
}
