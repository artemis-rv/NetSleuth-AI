import { AlertCircle } from 'lucide-react';
import { useMitreQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { MitreMappingResponse } from '../types';

function confidenceColor(conf: number | null): string {
  if (conf === null) return 'bg-slate-700/60 border-slate-600/40';
  if (conf >= 0.8) return 'bg-red-500/30 border-red-500/50';
  if (conf >= 0.6) return 'bg-orange-500/25 border-orange-500/40';
  if (conf >= 0.4) return 'bg-yellow-500/20 border-yellow-500/35';
  return 'bg-blue-500/15 border-blue-500/30';
}

function confidenceTextColor(conf: number | null): string {
  if (conf === null) return 'text-slate-400';
  if (conf >= 0.8) return 'text-red-300';
  if (conf >= 0.6) return 'text-orange-300';
  if (conf >= 0.4) return 'text-yellow-300';
  return 'text-blue-300';
}

interface MitreSectionProps {
  caseId: string;
}

export function MitreSection({ caseId }: MitreSectionProps) {
  const { data, isLoading, isError, error } = useMitreQuery(caseId, { page: 1, page_size: 100 });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Spinner size={28} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
        <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
        Failed to load MITRE mappings. {(error as Error)?.message}
      </div>
    );
  }

  if (!data || data.items.length === 0) {
    return (
      <EmptyState
        title="No MITRE Mappings"
        description="No ATT&CK technique mappings have been produced for this investigation yet."
      />
    );
  }

  // Group by tactic — derive from server data only
  const tacticMap = new Map<string, { tactic_id: string; tactic_name: string; techniques: MitreMappingResponse[] }>();

  for (const mapping of data.items) {
    if (!tacticMap.has(mapping.tactic_id)) {
      tacticMap.set(mapping.tactic_id, {
        tactic_id: mapping.tactic_id,
        tactic_name: mapping.tactic_name,
        techniques: [],
      });
    }
    tacticMap.get(mapping.tactic_id)!.techniques.push(mapping);
  }

  const tactics = Array.from(tacticMap.values()).sort((a, b) =>
    a.tactic_id.localeCompare(b.tactic_id),
  );

  return (
    <div className="space-y-4">
      {/* Legend */}
      <div className="flex items-center gap-4 text-xs text-muted">
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded border bg-red-500/30 border-red-500/50 inline-block" />
          High (≥80%)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded border bg-orange-500/25 border-orange-500/40 inline-block" />
          Medium (≥60%)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded border bg-yellow-500/20 border-yellow-500/35 inline-block" />
          Low (≥40%)
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-3 h-3 rounded border bg-blue-500/15 border-blue-500/30 inline-block" />
          Weak (&lt;40%)
        </span>
      </div>

      <p className="text-xs text-muted">
        {data.total.toLocaleString()} technique mapping{data.total !== 1 ? 's' : ''} across {tactics.length} tactic{tactics.length !== 1 ? 's' : ''}
      </p>

      {/* Tactic columns */}
      <div className="grid gap-4" style={{ gridTemplateColumns: `repeat(auto-fill, minmax(220px, 1fr))` }}>
        {tactics.map((tactic) => (
          <div
            key={tactic.tactic_id}
            className="border border-border-subtle rounded overflow-hidden"
          >
            {/* Tactic header */}
            <div className="bg-surface-elevated px-3 py-2 border-b border-border-subtle">
              <p className="text-[10px] font-semibold uppercase tracking-widest text-muted">
                {tactic.tactic_id}
              </p>
              <p className="text-xs font-medium text-primary mt-0.5">
                {tactic.tactic_name}
              </p>
            </div>

            {/* Technique cells */}
            <div className="p-2 space-y-1.5">
              {tactic.techniques.map((t) => (
                <div
                  key={t.mitre_mapping_id}
                  className={`rounded border px-2.5 py-2 transition-colors hover:opacity-90 ${confidenceColor(t.confidence)}`}
                  title={`${t.technique_id}: ${t.technique_name} — Confidence: ${t.confidence !== null ? `${Math.round(t.confidence * 100)}%` : 'unknown'}`}
                >
                  <p className={`text-[10px] font-mono font-semibold ${confidenceTextColor(t.confidence)}`}>
                    {t.technique_id}
                  </p>
                  <p className="text-[11px] text-primary leading-tight mt-0.5">
                    {t.technique_name}
                  </p>
                  {t.confidence !== null && (
                    <p className={`text-[10px] mt-1 tabular-nums ${confidenceTextColor(t.confidence)}`}>
                      {Math.round(t.confidence * 100)}% confidence
                    </p>
                  )}
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
