import { useState } from 'react';
import { AlertCircle, ChevronLeft, ChevronRight, Activity, ShieldAlert, BarChart } from 'lucide-react';
import { useBehaviorsQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import { BehaviorCard } from './BehaviorCard';
import { BehaviorDetailDrawer } from './BehaviorDetailDrawer';
import type { PaginationFilters } from '../types';

interface BehaviorsSectionProps {
  caseId: string;
}

export function BehaviorsSection({ caseId }: BehaviorsSectionProps) {
  const [filters, setFilters] = useState<PaginationFilters>({ page: 1, page_size: 50 });
  const [selectedBehaviorId, setSelectedBehaviorId] = useState<string | null>(null);
  
  const { data, isLoading, isError, error } = useBehaviorsQuery(caseId, filters);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 50)) : 0;
  const currentPage = filters.page ?? 1;

  // Compute metrics
  const total = data?.total || 0;
  const highCritical = data?.items.filter(b => b.severity?.toLowerCase() === 'high' || b.severity?.toLowerCase() === 'critical').length || 0;
  const avgConfidence = data?.items.length 
    ? Math.round(data.items.reduce((acc, b) => acc + (b.confidence || 0), 0) / data.items.length * 100) 
    : 0;

  return (
    <div className="space-y-6">
      {/* Header Metrics */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="p-4 rounded-lg border border-border-subtle bg-surface-elevated/30 flex items-center gap-4">
          <div className="p-2 rounded bg-blue-500/10 text-blue-400">
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-muted uppercase tracking-wider font-semibold">Total Behaviors</p>
            <p className="text-2xl font-bold text-primary">{total.toLocaleString()}</p>
          </div>
        </div>
        <div className="p-4 rounded-lg border border-border-subtle bg-surface-elevated/30 flex items-center gap-4">
          <div className="p-2 rounded bg-red-500/10 text-red-400">
            <ShieldAlert className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-muted uppercase tracking-wider font-semibold">High/Critical</p>
            <p className="text-2xl font-bold text-primary">{highCritical}</p>
          </div>
        </div>
        <div className="p-4 rounded-lg border border-border-subtle bg-surface-elevated/30 flex items-center gap-4">
          <div className="p-2 rounded bg-green-500/10 text-green-400">
            <BarChart className="w-5 h-5" />
          </div>
          <div>
            <p className="text-xs text-muted uppercase tracking-wider font-semibold">Avg Confidence</p>
            <p className="text-2xl font-bold text-primary">{avgConfidence}%</p>
          </div>
        </div>
      </div>

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
        <div className="space-y-4">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-primary">Behavior Detections</h3>
          </div>
          
          <div className="flex flex-col">
            {data.items.map((beh) => (
              <BehaviorCard
                key={beh.behavior_id}
                behavior={beh}
                selected={selectedBehaviorId === beh.behavior_id}
                onClick={() => setSelectedBehaviorId(beh.behavior_id)}
              />
            ))}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between pt-4">
              <p className="text-[12px] text-muted">
                Showing {((currentPage - 1) * (filters.page_size ?? 50)) + 1}–{Math.min(currentPage * (filters.page_size ?? 50), data.total)} of {data.total.toLocaleString()} total
              </p>
              <div className="flex items-center gap-2">
                <div className="flex items-center gap-1.5 mr-2">
                  <span className="text-[10px] uppercase tracking-widest text-muted font-bold">PAGE</span>
                  <input
                    type="number"
                    min={1}
                    max={totalPages}
                    defaultValue={currentPage}
                    key={`page-input-${currentPage}`}
                    onKeyDown={(e) => {
                      if (e.key === 'Enter') {
                        const p = parseInt((e.target as HTMLInputElement).value);
                        if (!isNaN(p) && p >= 1 && p <= totalPages) {
                          setFilters((f) => ({ ...f, page: p }));
                        } else {
                          (e.target as HTMLInputElement).value = currentPage.toString();
                        }
                      }
                    }}
                    onBlur={(e) => {
                      const p = parseInt(e.target.value);
                      if (!isNaN(p) && p >= 1 && p <= totalPages && p !== currentPage) {
                        setFilters((f) => ({ ...f, page: p }));
                      } else {
                        e.target.value = currentPage.toString();
                      }
                    }}
                    className="w-12 h-7 px-1 text-center text-[12px] font-mono bg-surface/50 border border-border-subtle rounded text-primary focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent/50 [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                    title="Type page number and press Enter"
                    aria-label="Jump to page"
                  />
                  <span className="text-[10px] uppercase tracking-widest text-muted font-bold">OF {totalPages}</span>
                </div>
                
                <button
                  id="behaviors-prev-page"
                  onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
                  disabled={currentPage <= 1}
                  className="flex items-center gap-1 px-2.5 py-1.5 text-[12px] rounded border border-border-subtle text-secondary hover:text-primary hover:bg-surface-elevated disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-3.5 w-3.5" /> Prev
                </button>
                <button
                  id="behaviors-next-page"
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
        </div>
      )}

      {/* Detail Drawer */}
      <BehaviorDetailDrawer
        caseId={caseId}
        behaviorId={selectedBehaviorId}
        onClose={() => setSelectedBehaviorId(null)}
      />
    </div>
  );
}
