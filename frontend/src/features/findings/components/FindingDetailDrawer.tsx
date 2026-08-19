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
        className="fixed right-0 top-0 h-full w-full max-w-lg bg-surface border-l border-border-subtle z-50 overflow-y-auto shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-label="Finding detail"
      >
        {/* Header */}
        <div className="sticky top-0 bg-surface border-b border-border-subtle px-6 py-4 flex items-center justify-between z-10">
          <h2 className="text-sm font-semibold text-primary">Finding Detail</h2>
          <button
            onClick={onClose}
            className="rounded p-1 hover:bg-surface-elevated text-muted hover:text-primary transition-colors"
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
                <Section title="Feature Metrics" icon={Layers}>
                  <div className="space-y-1">
                    {Object.entries(data.feature_attribution)
                      .sort(([, a], [, b]) => Math.abs(b) - Math.abs(a))
                      .slice(0, 10)
                      .map(([feat, score]) => {
                        const isDecimal = score % 1 !== 0;
                        const formatted = isDecimal ? score.toFixed(2) : Math.round(score).toLocaleString();
                        return (
                          <div key={feat} className="flex justify-between py-0.5">
                            <span className="text-xs text-muted font-mono truncate max-w-[60%]">{feat}</span>
                            <span className="text-xs tabular-nums font-medium text-emerald-400">
                              {formatted}
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
