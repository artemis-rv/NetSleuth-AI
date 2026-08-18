import { AlertCircle, Link2, ChevronRight } from 'lucide-react';
import { useAttackChainQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';

function ConfidenceBadge({ value }: { value: number | null }) {
  if (value === null) return null;
  const pct = Math.round(value * 100);
  const color = pct >= 80 ? 'text-red-400 bg-red-500/10 border-red-500/30' : pct >= 60 ? 'text-orange-400 bg-orange-500/10 border-orange-500/30' : 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30';
  return (
    <span className={`text-xs font-medium rounded border px-2 py-0.5 tabular-nums ${color}`}>
      {pct}% confidence
    </span>
  );
}

interface AttackChainSectionProps {
  caseId: string;
}

export function AttackChainSection({ caseId }: AttackChainSectionProps) {
  const { data, isLoading, isError, error } = useAttackChainQuery(caseId);

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
        Failed to load attack chain. {(error as Error)?.message}
      </div>
    );
  }

  if (!data) {
    return (
      <EmptyState
        title="No Attack Chain"
        description="No attack chain has been reconstructed for this investigation yet."
      />
    );
  }

  const stageEntries = Object.entries(data.stages);

  if (stageEntries.length === 0) {
    return (
      <EmptyState
        title="No Attack Stages"
        description="The attack chain exists but contains no stages."
      />
    );
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="flex items-center gap-2">
          <Link2 className="h-4 w-4 text-accent" aria-hidden="true" />
          <span className="text-sm font-medium text-primary">
            Attack Chain
          </span>
        </div>
        <ConfidenceBadge value={data.confidence} />
        <span className="text-xs text-muted tabular-nums ml-auto">
          Updated {new Date(data.updated_at).toLocaleString()}
        </span>
      </div>

      {/* Chain ID */}
      <p className="text-xs text-muted font-mono">ID: {data.chain_id}</p>

      {/* Stage cards in a horizontal chain layout */}
      <div className="space-y-3">
        {stageEntries.map(([stageName, stageData], idx) => {
          const isLast = idx === stageEntries.length - 1;
          // stageData can be an object with arbitrary fields
          const stageFields = typeof stageData === 'object' && stageData !== null
            ? Object.entries(stageData as Record<string, unknown>)
            : [];

          return (
            <div key={stageName} className="flex items-start gap-3">
              {/* Stage card */}
              <div className="flex-1 border border-border-subtle rounded p-3.5 space-y-2 hover:bg-surface-elevated/30 transition-colors">
                {/* Stage header */}
                <div className="flex items-center gap-2">
                  <div className="flex-shrink-0 w-6 h-6 rounded-full border border-accent/50 bg-accent/10 flex items-center justify-center">
                    <span className="text-[10px] font-bold text-accent">{idx + 1}</span>
                  </div>
                  <h3 className="text-sm font-medium text-primary capitalize">
                    {stageName.replace(/_/g, ' ')}
                  </h3>
                </div>

                {/* Stage fields */}
                {stageFields.length > 0 && (
                  <div className="pl-8 space-y-1">
                    {stageFields.map(([k, v]) => (
                      <div key={k} className="flex gap-3 text-xs">
                        <span className="text-muted w-32 flex-shrink-0 font-mono">{k}</span>
                        <span className="text-secondary font-mono break-all">
                          {Array.isArray(v)
                            ? (v as unknown[]).join(', ')
                            : typeof v === 'object' && v !== null
                            ? JSON.stringify(v)
                            : String(v)}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Connector arrow */}
              {!isLast && (
                <div className="flex-shrink-0 mt-4 text-muted">
                  <ChevronRight className="h-5 w-5" aria-hidden="true" />
                </div>
              )}

              {/* Spacer for last item */}
              {isLast && <div className="w-5" />}
            </div>
          );
        })}
      </div>
    </div>
  );
}
