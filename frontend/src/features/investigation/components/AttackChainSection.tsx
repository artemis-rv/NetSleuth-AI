import { AlertCircle, Link2, ShieldAlert, Tag, Clock } from 'lucide-react';
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

interface AttackChainStage {
  stage_id?: string;
  name?: string;
  finding_ids?: string[];
  event_ids?: string[];
  timestamp?: string;
  technique_id?: string;
  [key: string]: unknown;
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

  // Extract stages list and chain status from response payload
  let stagesList: AttackChainStage[] = [];
  let chainStatus = 'potential';

  if (Array.isArray(data.stages)) {
    stagesList = data.stages;
  } else if (data.stages && typeof data.stages === 'object') {
    const rawObj = data.stages as Record<string, unknown>;
    if (Array.isArray(rawObj.stages)) {
      stagesList = rawObj.stages as AttackChainStage[];
    }
    if (typeof rawObj.status === 'string') {
      chainStatus = rawObj.status;
    }
  }

  if (stagesList.length === 0) {
    return (
      <EmptyState
        title="No Attack Stages"
        description="The attack chain exists but contains no progressive stages."
      />
    );
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center gap-3 flex-wrap bg-surface-elevated/40 border border-border-subtle rounded-lg p-4">
        <div className="flex items-center gap-2">
          <Link2 className="h-5 w-5 text-accent" aria-hidden="true" />
          <span className="text-sm font-semibold text-primary">
            {data.title || 'Reconstructed Attack Chain'}
          </span>
        </div>

        <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-semibold uppercase tracking-wide bg-orange-500/15 text-orange-400 border border-orange-500/30">
          Status: {chainStatus}
        </span>

        <ConfidenceBadge value={data.confidence} />

        <span className="text-xs text-muted tabular-nums ml-auto">
          Updated {new Date(data.updated_at).toLocaleString()}
        </span>
      </div>

      {/* Summary */}
      {data.summary && (
        <p className="text-xs text-secondary leading-relaxed px-1">
          {data.summary}
        </p>
      )}

      {/* Stage Progression Flow */}
      <div className="space-y-3">
        {stagesList.map((stage, idx) => {
          const isLast = idx === stagesList.length - 1;
          const stageName = stage.name || stage.stage_id || `Stage ${idx + 1}`;
          const findingIds = Array.isArray(stage.finding_ids) ? stage.finding_ids : [];
          const eventIds = Array.isArray(stage.event_ids) ? stage.event_ids : [];

          return (
            <div key={stage.stage_id || idx} className="space-y-3">
              <div className="border border-border-subtle rounded-lg p-4 bg-surface hover:bg-surface-elevated/30 transition-colors">
                {/* Stage Header */}
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <div className="flex items-center gap-3">
                    <div className="flex-shrink-0 w-7 h-7 rounded-full border border-accent/60 bg-accent/15 flex items-center justify-center">
                      <span className="text-xs font-bold text-accent">{idx + 1}</span>
                    </div>
                    <div>
                      <h3 className="text-sm font-semibold text-primary">
                        {stageName}
                      </h3>
                      {stage.stage_id && (
                        <p className="text-xs text-muted font-mono">{stage.stage_id}</p>
                      )}
                    </div>
                  </div>

                  {stage.timestamp && (
                    <span className="flex items-center gap-1 text-xs text-muted tabular-nums">
                      <Clock className="h-3 w-3" />
                      {new Date(stage.timestamp).toLocaleString()}
                    </span>
                  )}
                </div>

                {/* Associated Findings & Evidence */}
                {(findingIds.length > 0 || eventIds.length > 0) && (
                  <div className="mt-3 pt-3 border-t border-border-subtle/60 flex items-center gap-2 flex-wrap">
                    {findingIds.map((fId) => (
                      <span
                        key={fId}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-red-500/10 text-red-400 border border-red-500/25"
                      >
                        <ShieldAlert className="h-3 w-3" />
                        {fId}
                      </span>
                    ))}
                    {eventIds.map((eId) => (
                      <span
                        key={eId}
                        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-blue-500/10 text-blue-400 border border-blue-500/25"
                      >
                        <Tag className="h-3 w-3" />
                        {eId}
                      </span>
                    ))}
                  </div>
                )}
              </div>

              {/* Step connector */}
              {!isLast && (
                <div className="flex items-center justify-center py-0.5 text-muted">
                  <div className="w-px h-3 bg-border-subtle" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
