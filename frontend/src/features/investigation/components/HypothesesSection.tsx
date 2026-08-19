import { AlertCircle, HelpCircle, FileText } from 'lucide-react';
import { useHypothesesQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';

function StatusBadge({ status }: { status: string }) {
  const color = status.toLowerCase() === 'confirmed' ? 'bg-green-500/10 text-green-400 border-green-500/30' : 
                status.toLowerCase() === 'rejected' ? 'bg-red-500/10 text-red-400 border-red-500/30' : 
                'bg-blue-500/10 text-blue-400 border-blue-500/30';
  return (
    <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded border ${color}`}>
      {status}
    </span>
  );
}

export function HypothesesSection({ caseId }: { caseId: string }) {
  const { data, isLoading, isError, error } = useHypothesesQuery(caseId);

  if (isLoading) return <div className="flex justify-center py-8"><Spinner size={24} /></div>;
  
  if (isError) return (
    <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
      <AlertCircle className="h-4 w-4" /> Failed to load hypotheses. {(error as Error)?.message}
    </div>
  );

  if (!data || data.items.length === 0) return (
    <EmptyState title="No Hypotheses" description="No investigative hypotheses have been formulated yet." />
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-sm text-muted">
        <HelpCircle className="h-4 w-4" />
        <span>{data.total} Hypotheses</span>
      </div>

      <div className="grid gap-4">
        {data.items.map(h => (
          <div key={h.hypothesis_id} className="border border-border-subtle rounded-lg p-4 bg-surface hover:bg-surface-elevated/40 transition-colors">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs font-mono text-muted bg-surface-elevated px-2 py-0.5 rounded border border-border-subtle">
                    {h.hypothesis_type}
                  </span>
                  <StatusBadge status={h.status} />
                </div>
                <h4 className="text-sm font-semibold text-primary">{h.statement}</h4>
              </div>
              <div className="text-right">
                <div className="text-xs font-medium text-accent">
                  {Math.round(h.confidence * 100)}% Conf.
                </div>
              </div>
            </div>

            <div className="mt-4 flex gap-2 flex-wrap">
              {h.supporting_evidence_ids.length > 0 && (
                <span className="inline-flex items-center gap-1 text-[11px] bg-slate-500/10 text-slate-300 border border-slate-500/20 px-2 py-0.5 rounded">
                  <FileText className="h-3 w-3" /> {h.supporting_evidence_ids.length} Evidence
                </span>
              )}
              {h.supporting_finding_ids && h.supporting_finding_ids.length > 0 && (
                <span className="inline-flex items-center gap-1 text-[11px] bg-red-500/10 text-red-300 border border-red-500/20 px-2 py-0.5 rounded">
                  <AlertCircle className="h-3 w-3" /> {h.supporting_finding_ids.length} Findings
                </span>
              )}
            </div>

            {h.supporting_reasons && h.supporting_reasons.length > 0 && (
              <div className="mt-3 pt-3 border-t border-border-subtle">
                <p className="text-[11px] text-muted mb-1 uppercase tracking-wider font-semibold">Reasons</p>
                <ul className="list-disc list-inside text-xs text-secondary space-y-1">
                  {h.supporting_reasons.map((r: any, i: number) => <li key={i}>{r}</li>)}
                </ul>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
