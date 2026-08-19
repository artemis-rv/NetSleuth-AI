import { AlertCircle, FileCheck2, FileText } from 'lucide-react';
import { useHypothesisValidationsQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';

export function ValidationsSection({ caseId }: { caseId: string }) {
  const { data, isLoading, isError, error } = useHypothesisValidationsQuery(caseId);

  if (isLoading) return <div className="flex justify-center py-8"><Spinner size={24} /></div>;
  
  if (isError) return (
    <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
      <AlertCircle className="h-4 w-4" /> Failed to load validations. {(error as Error)?.message}
    </div>
  );

  if (!data || data.items.length === 0) return (
    <EmptyState title="No Validations" description="No hypotheses have been validated yet." />
  );

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2 text-sm text-muted">
        <FileCheck2 className="h-4 w-4" />
        <span>{data.total} Validation Records</span>
      </div>

      <div className="grid gap-4">
        {data.items.map(v => (
          <div key={v.validation_id} className="border border-border-subtle rounded-lg p-4 bg-surface hover:bg-surface-elevated/40 transition-colors">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="flex items-center gap-2 mb-1">
                  <span className={`text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded border ${
                    v.validation_status.toLowerCase() === 'confirmed' ? 'bg-green-500/10 text-green-400 border-green-500/30' :
                    v.validation_status.toLowerCase() === 'rejected' ? 'bg-red-500/10 text-red-400 border-red-500/30' :
                    'bg-yellow-500/10 text-yellow-400 border-yellow-500/30'
                  }`}>
                    {v.validation_status}
                  </span>
                </div>
                <p className="text-xs text-muted font-mono mt-1">Hypothesis: {v.hypothesis_id}</p>
              </div>
              <div className="text-right">
                <div className="text-xs font-medium text-accent">
                  {Math.round(v.confidence * 100)}% Conf.
                </div>
                <div className="text-[10px] text-muted mt-1">
                  {new Date(v.validated_at).toLocaleString()}
                </div>
              </div>
            </div>

            <div className="mt-4 grid grid-cols-1 md:grid-cols-2 gap-4">
              {(v.supporting_reasons?.length || v.supporting_evidence_ids?.length) ? (
                <div className="bg-green-500/5 border border-green-500/10 rounded p-3">
                  <p className="text-[10px] uppercase tracking-wider font-semibold text-green-400 mb-2">Supporting</p>
                  {v.supporting_evidence_ids && v.supporting_evidence_ids.length > 0 && (
                    <p className="text-xs text-secondary mb-1">
                      <FileText className="h-3 w-3 inline mr-1" /> {v.supporting_evidence_ids.length} Evidence Items
                    </p>
                  )}
                  {v.supporting_reasons && v.supporting_reasons.map((r: any, i: number) => (
                    <p key={i} className="text-xs text-secondary flex items-start gap-1">
                      <span className="text-green-500/50">•</span> {r}
                    </p>
                  ))}
                </div>
              ) : null}

              {(v.contradicting_reasons?.length || v.contradicting_evidence_ids?.length) ? (
                <div className="bg-red-500/5 border border-red-500/10 rounded p-3">
                  <p className="text-[10px] uppercase tracking-wider font-semibold text-red-400 mb-2">Contradicting</p>
                  {v.contradicting_evidence_ids && v.contradicting_evidence_ids.length > 0 && (
                    <p className="text-xs text-secondary mb-1">
                      <FileText className="h-3 w-3 inline mr-1" /> {v.contradicting_evidence_ids.length} Evidence Items
                    </p>
                  )}
                  {v.contradicting_reasons && v.contradicting_reasons.map((r: any, i: number) => (
                    <p key={i} className="text-xs text-secondary flex items-start gap-1">
                      <span className="text-red-500/50">•</span> {r}
                    </p>
                  ))}
                </div>
              ) : null}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
