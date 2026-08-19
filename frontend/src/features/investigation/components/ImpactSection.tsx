import { AlertCircle, AlertTriangle, FileText } from 'lucide-react';
import { useImpactAssessmentsQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';

export function ImpactSection({ caseId }: { caseId: string }) {
  const { data, isLoading, isError, error } = useImpactAssessmentsQuery(caseId);

  if (isLoading) return <div className="flex justify-center py-8"><Spinner size={24} /></div>;
  
  if (isError) return (
    <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
      <AlertCircle className="h-4 w-4" /> Failed to load impact assessments. {(error as Error)?.message}
    </div>
  );

  if (!data || data.items.length === 0) return (
    <EmptyState title="No Impact Assessments" description="No business or technical impact has been assessed yet." />
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-sm text-muted">
        <AlertTriangle className="h-4 w-4" />
        <span>{data.total} Impact Assessments</span>
      </div>

      <div className="grid gap-4">
        {data.items.map(impact => (
          <div key={impact.impact_id} className="border border-border-subtle rounded-lg p-4 bg-surface hover:bg-surface-elevated/40 transition-colors">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-2">
                  <span className="text-xs font-mono text-muted bg-surface-elevated px-2 py-0.5 rounded border border-border-subtle">
                    {impact.category}
                  </span>
                  <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded border ${
                    impact.status.toLowerCase() === 'confirmed' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                    'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                  }`}>
                    {impact.status}
                  </span>
                </div>
                <h4 className="text-sm font-semibold text-primary">{impact.statement}</h4>
              </div>
              <div className="text-right">
                <div className="text-xs font-medium text-accent">
                  {Math.round(impact.confidence * 100)}% Conf.
                </div>
              </div>
            </div>

            <div className="mt-4 flex gap-2 flex-wrap">
              {impact.supporting_evidence_ids.length > 0 && (
                <span className="inline-flex items-center gap-1 text-[11px] bg-slate-500/10 text-slate-300 border border-slate-500/20 px-2 py-0.5 rounded">
                  <FileText className="h-3 w-3" /> {impact.supporting_evidence_ids.length} Evidence
                </span>
              )}
              {impact.affected_entity_ids && impact.affected_entity_ids.length > 0 && (
                <span className="inline-flex items-center gap-1 text-[11px] bg-orange-500/10 text-orange-300 border border-orange-500/20 px-2 py-0.5 rounded">
                  <AlertCircle className="h-3 w-3" /> {impact.affected_entity_ids.length} Affected Entities
                </span>
              )}
            </div>

            {impact.rationale && impact.rationale.length > 0 && (
              <div className="mt-3 pt-3 border-t border-border-subtle">
                <p className="text-[11px] text-muted mb-1 uppercase tracking-wider font-semibold">Rationale</p>
                <ul className="list-disc list-inside text-xs text-secondary space-y-1">
                  {impact.rationale.map((r: any, i: number) => <li key={i}>{r}</li>)}
                </ul>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
