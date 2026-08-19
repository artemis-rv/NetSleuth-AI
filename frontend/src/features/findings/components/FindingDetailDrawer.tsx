import { X, AlertTriangle, Brain, Cpu, FileText, Hash, Layers } from 'lucide-react';
import { useFindingDetailQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';

interface FindingDetailDrawerProps {
  findingId: string | null;
  onClose: () => void;
}

function ConfidenceBar({ value }: { value: number | null }) {
  if (value === null) return <span className="text-xs text-muted">—</span>;
  const pct = Math.min(100, Math.max(0, value * 100));
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-surface-elevated overflow-hidden">
        <div
          className="h-full rounded-full bg-accent"
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className="text-xs text-secondary tabular-nums w-10 text-right">{(value * 100).toFixed(0)}%</span>
    </div>
  );
}

function Section({ title, icon: Icon, children }: { title: string; icon: any; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 pb-1 border-b border-border-subtle">
        <Icon className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
        <h3 className="text-xs font-semibold uppercase tracking-widest text-muted">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function KVRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1">
      <span className="text-xs text-muted flex-shrink-0 w-40">{label}</span>
      <span className="text-xs text-primary text-right font-mono break-all">{value ?? '—'}</span>
    </div>
  );
}

export function FindingDetailDrawer({ findingId, onClose }: FindingDetailDrawerProps) {
  const { data, isLoading } = useFindingDetailQuery(findingId);

  if (!findingId) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/40 z-40 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer */}
      <aside
        className="fixed right-0 top-0 h-full w-full max-w-[480px] bg-surface border-l border-border-subtle z-50 overflow-y-auto shadow-2xl transition-transform"
        role="dialog"
        aria-modal="true"
        aria-label="Finding detail"
      >
        {/* Header */}
        <div className="sticky top-0 bg-surface/95 backdrop-blur-md border-b border-border-subtle px-6 py-5 flex items-start justify-between z-10 shadow-sm">
          <div className="space-y-1.5 pr-4">
            <h2 className="text-[11px] font-bold text-muted uppercase tracking-widest flex items-center gap-2">
              <AlertTriangle className="h-3 w-3" aria-hidden="true" />
              Finding
            </h2>
            {data ? (
              <>
                <p className="text-[14px] font-mono font-medium text-primary leading-tight">
                  {data.activity.replace(/_/g, ' ')}
                </p>
                <div className="flex items-center gap-2.5 pt-1">
                  <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-widest ${
                    data.severity === 'CRITICAL' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                    data.severity === 'HIGH' ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                    data.severity === 'MEDIUM' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' :
                    data.severity === 'LOW' ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' :
                    'bg-slate-500/10 text-slate-400 border-slate-500/20'
                  }`}>
                    {data.severity}
                  </span>
                  <span className="text-[11px] text-muted font-mono">Risk {data.risk_score?.toFixed(2) ?? '—'}</span>
                </div>
              </>
            ) : (
              <p className="text-sm font-semibold text-primary">Loading detail...</p>
            )}
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 hover:bg-surface-elevated text-muted hover:text-primary transition-colors mt-0.5"
            aria-label="Close finding detail"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Body */}
        <div className="px-6 py-5 space-y-6">
          {isLoading && (
            <div className="flex items-center justify-center py-16">
              <Spinner size={28} />
            </div>
          )}

          {data && (
            <>
              {/* Identity */}
              <Section title="Identity" icon={Hash}>
                <KVRow label="Finding ID" value={data.finding_id} />
                <KVRow label="Version" value={data.version} />
                <KVRow label="Activity" value={data.activity.replace(/_/g, ' ')} />
                <KVRow label="Detection Method" value={data.detection_method} />
                <KVRow label="Decision State" value={data.decision_state.replace(/_/g, ' ')} />
                <KVRow label="Severity" value={data.severity} />
                <KVRow label="Detected At" value={new Date(data.detected_at).toLocaleString()} />
                {data.first_seen && (
                  <KVRow label="First Seen" value={new Date(data.first_seen).toLocaleString()} />
                )}
                {data.last_seen && (
                  <KVRow label="Last Seen" value={new Date(data.last_seen).toLocaleString()} />
                )}
              </Section>

              {/* Scoring */}
              <Section title="Risk Scoring" icon={AlertTriangle}>
                <div className="space-y-3">
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-xs text-muted">Risk Score</span>
                      <span className="text-xs text-secondary tabular-nums">
                        {data.risk_score?.toFixed(3) ?? '—'}
                      </span>
                    </div>
                    <ConfidenceBar value={data.risk_score} />
                  </div>
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-xs text-muted">Confidence</span>
                      <span className="text-xs text-secondary tabular-nums">
                        {data.confidence?.toFixed(3) ?? '—'}
                      </span>
                    </div>
                    <ConfidenceBar value={data.confidence} />
                  </div>
                  <div>
                    <div className="flex justify-between mb-1">
                      <span className="text-xs text-muted">Anomaly Score</span>
                      <span className="text-xs text-secondary tabular-nums">
                        {data.anomaly_score?.toFixed(3) ?? '—'}
                      </span>
                    </div>
                    <ConfidenceBar value={data.anomaly_score} />
                  </div>
                  <div className="flex justify-between py-1">
                    <span className="text-xs text-muted">Anomaly Detected</span>
                    <span className={`text-xs font-medium ${data.anomaly_detected ? 'text-red-400' : 'text-slate-400'}`}>
                      {data.anomaly_detected ? 'YES' : 'NO'}
                    </span>
                  </div>
                </div>
              </Section>

              {/* Model Info */}
              <Section title="Model Provenance" icon={Brain}>
                <KVRow label="Model Version" value={data.model_version} />
                <KVRow label="Feature Schema" value={data.feature_schema_version} />
                <KVRow label="Risk Policy" value={data.risk_policy_version} />
              </Section>

              {/* Classification Probabilities */}
              {data.classification_probabilities && Object.keys(data.classification_probabilities).length > 0 && (
                <Section title="Classification Probabilities" icon={Cpu}>
                  <div className="space-y-2">
                    {Object.entries(data.classification_probabilities)
                      .sort(([, a], [, b]) => b - a)
                      .map(([label, prob]) => (
                        <div key={label}>
                          <div className="flex justify-between mb-1">
                            <span className="text-xs text-muted font-mono">{label}</span>
                            <span className="text-xs text-secondary tabular-nums">{(prob * 100).toFixed(1)}%</span>
                          </div>
                          <ConfidenceBar value={prob} />
                        </div>
                      ))}
                  </div>
                </Section>
              )}

              {/* Feature Metrics */}
              {data.feature_attribution && Object.keys(data.feature_attribution).length > 0 && (
                <Section title="Feature Attribution" icon={Layers}>
                  <div className="space-y-0.5 mt-1 border border-border-subtle rounded-md overflow-hidden bg-surface-elevated/30">
                    {Object.entries(data.feature_attribution)
                      .sort(([, a], [, b]) => Math.abs(b) - Math.abs(a))
                      .map(([feat, score]) => {
                        const isDecimal = score % 1 !== 0;
                        const formatted = isDecimal ? score.toFixed(3) : Math.round(score).toLocaleString();
                        const sign = score > 0 ? '+' : '';
                        const colorClass = score > 0 ? 'text-orange-400' : 'text-blue-400';
                        return (
                          <div key={feat} className="flex justify-between items-center py-1.5 px-3 border-b border-border-subtle/50 last:border-0 hover:bg-surface-elevated/50 transition-colors">
                            <span className="text-[11px] text-secondary font-mono truncate pr-4">{feat}</span>
                            <span className={`text-[11px] tabular-nums font-medium font-mono ${colorClass}`}>
                              {sign}{formatted}
                            </span>
                          </div>
                        );
                      })}
                  </div>
                </Section>
              )}

              {/* Rationale */}
              {data.rationale && (
                <Section title="Rationale" icon={FileText}>
                  <p className="text-sm text-secondary leading-relaxed whitespace-pre-wrap">
                    {data.rationale}
                  </p>
                </Section>
              )}

              {/* References */}
              <Section title="References" icon={Hash}>
                <KVRow label="Package ID" value={data.package_id} />
                <KVRow label="Acquisition ID" value={data.acquisition_id} />
                {data.supersedes_id && (
                  <KVRow label="Supersedes" value={data.supersedes_id} />
                )}
              </Section>
            </>
          )}
        </div>
      </aside>
    </>
  );
}
