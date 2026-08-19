import { useState } from 'react';
import { AlertCircle, ChevronDown, ChevronRight, ChevronLeft } from 'lucide-react';
import { useEntitiesQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { EntityResponse, PaginationFilters } from '../types';

const ENTITY_TYPE_STYLES: Record<string, string> = {
  ip_address: 'bg-blue-500/15 text-blue-400',
  domain: 'bg-purple-500/15 text-purple-400',
  host: 'bg-teal-500/15 text-teal-400',
  user: 'bg-green-500/15 text-green-400',
  file: 'bg-yellow-500/15 text-yellow-400',
  process: 'bg-orange-500/15 text-orange-400',
  service: 'bg-slate-500/15 text-slate-400',
};

function RiskBar({ score }: { score: number | null }) {
  if (score === null) return <span className="text-xs text-muted">—</span>;
  const pct = Math.min(100, Math.max(0, score * 100));
  const color = score >= 0.8 ? 'bg-red-500' : score >= 0.6 ? 'bg-orange-400' : score >= 0.4 ? 'bg-yellow-400' : 'bg-blue-400';
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-16 h-1.5 rounded-full bg-surface-elevated overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-secondary tabular-nums">{score.toFixed(2)}</span>
    </div>
  );
}

function EntityDetailExpand({ entity }: { entity: EntityResponse }) {
  const [open, setOpen] = useState(false);
  const propCount = entity.properties ? Object.keys(entity.properties).length : 0;

  if (propCount === 0) return null;

  return (
    <div>
      <button
        onClick={() => setOpen((o) => !o)}
        className="flex items-center gap-1 text-xs text-muted hover:text-primary transition-colors mt-1"
        aria-expanded={open}
      >
        {open ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />}
        {propCount} propert{propCount !== 1 ? 'ies' : 'y'}
      </button>
      {open && (
        <div className="mt-1.5 pl-4 border-l border-border-subtle space-y-0.5">
          {Object.entries(entity.properties!).map(([k, v]) => (
            <div key={k} className="flex gap-3 text-xs">
              <span className="text-muted font-mono w-32 flex-shrink-0 truncate">{k}</span>
              <span className="text-secondary font-mono break-all">{String(v)}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

interface EntitiesSectionProps {
  caseId: string;
}

export function EntitiesSection({ caseId }: EntitiesSectionProps) {
  const [filters, setFilters] = useState<PaginationFilters>({ page: 1, page_size: 50 });
  const { data, isLoading, isError, error } = useEntitiesQuery(caseId, filters);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 50)) : 0;
  const currentPage = filters.page ?? 1;

  return (
    <div className="space-y-4">
      {data && (
        <p className="text-xs text-muted">
          {data.total.toLocaleString()} entit{data.total !== 1 ? 'ies' : 'y'} extracted
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
          Failed to load entities. {(error as Error)?.message}
        </div>
      )}

      {data && data.items.length === 0 && (
        <EmptyState title="No Entities" description="No entities have been extracted for this investigation." />
      )}

      {data && data.items.length > 0 && (
        <>
          <div className="space-y-2">
            {data.items.map((entity) => {
              const typeStyle = ENTITY_TYPE_STYLES[entity.entity_type?.toLowerCase()] ?? 'bg-slate-500/15 text-slate-400';
              return (
                <div
                  key={entity.entity_id}
                  className="border border-border-subtle rounded p-3 space-y-1.5 hover:bg-surface-elevated/30 transition-colors"
                >
                  <div className="flex items-start gap-3">
                    <div className="flex-1 min-w-0 space-y-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${typeStyle}`}>
                          {entity.entity_type.replace(/_/g, ' ')}
                        </span>
                        <span className="text-sm text-primary font-mono font-medium truncate">
                          {entity.name || (entity as { label?: string }).label || entity.entity_id}
                        </span>
                      </div>
                      <EntityDetailExpand entity={entity} />
                    </div>
                    <div className="flex-shrink-0">
                      <RiskBar score={entity.risk_score} />
                    </div>
                  </div>
                </div>
              );
            })}
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
                  id="entities-prev-page"
                  onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
                  disabled={currentPage <= 1}
                  className="flex items-center gap-1 px-2.5 py-1.5 text-[12px] rounded border border-border-subtle text-secondary hover:text-primary hover:bg-surface-elevated disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
                  aria-label="Previous page"
                >
                  <ChevronLeft className="h-3.5 w-3.5" /> Prev
                </button>
                <button
                  id="entities-next-page"
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
    </div>
  );
}
