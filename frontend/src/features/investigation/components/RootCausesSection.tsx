import { AlertCircle, Target, FileText } from 'lucide-react';
import { useRootCausesQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';

export function RootCausesSection({ caseId }: { caseId: string }) {
  const { data, isLoading, isError, error } = useRootCausesQuery(caseId);

  if (isLoading) return <div className="flex justify-center py-8"><Spinner size={24} /></div>;
  
  if (isError) return (
    <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
      <AlertCircle className="h-4 w-4" /> Failed to load root causes. {(error as Error)?.message}
    </div>
  );

  if (!data || data.items.length === 0) return (
    <EmptyState title="No Root Causes" description="No root causes have been identified yet." />
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-sm text-muted">
        <Target className="h-4 w-4" />
        <span>{data.total} Identified Root Causes</span>
      </div>

      <div className="grid gap-4">
        {data.items.map(rc => (
          <div key={rc.root_cause_id} className="border border-border-subtle rounded-lg p-4 bg-surface hover:bg-surface-elevated/40 transition-colors">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded border ${
                    rc.status.toLowerCase() === 'confirmed' ? 'bg-green-500/10 text-green-400 border-green-500/30' :
                    'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                  }`}>
                    {rc.status}
                  </span>
                </div>
                <h4 className="text-sm font-semibold text-primary">{rc.statement}</h4>
              </div>
              <div className="text-right">
                <div className="text-xs font-medium text-accent">
                  {Math.round(rc.confidence * 100)}% Conf.
                </div>
              </div>
            </div>

            <div className="mt-4 flex gap-2 flex-wrap">
              {rc.supporting_evidence_ids.length > 0 && (
                <span className="inline-flex items-center gap-1 text-[11px] bg-slate-500/10 text-slate-300 border border-slate-500/20 px-2 py-0.5 rounded">
                  <FileText className="h-3 w-3" /> {rc.supporting_evidence_ids.length} Evidence
                </span>
              )}
              {rc.supporting_hypothesis_ids && rc.supporting_hypothesis_ids.length > 0 && (
                <span className="inline-flex items-center gap-1 text-[11px] bg-blue-500/10 text-blue-300 border border-blue-500/20 px-2 py-0.5 rounded">
                  <Target className="h-3 w-3" /> {rc.supporting_hypothesis_ids.length} Hypotheses
                </span>
              )}
            </div>

            {rc.rationale && rc.rationale.length > 0 && (
              <div className="mt-3 pt-3 border-t border-border-subtle">
                <p className="text-[11px] text-muted mb-1 uppercase tracking-wider font-semibold">Rationale</p>
                <ul className="list-disc list-inside text-xs text-secondary space-y-1">
                  {rc.rationale.map((r: any, i: number) => <li key={i}>{r}</li>)}
                </ul>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
