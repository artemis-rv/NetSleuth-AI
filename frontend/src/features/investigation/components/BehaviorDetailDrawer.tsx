
import { X, ExternalLink, GitMerge, List, Shield, Fingerprint, Clock, Activity } from 'lucide-react';
import { useBehaviorDetailQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';

interface BehaviorDetailDrawerProps {
  caseId: string;
  behaviorId: string | null;
  onClose: () => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'text-red-400 bg-red-500/10 border-red-500/20',
  high: 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  medium: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  low: 'text-blue-400 bg-blue-500/10 border-blue-500/20',
  info: 'text-slate-400 bg-slate-500/10 border-slate-500/20',
};

export function BehaviorDetailDrawer({ caseId, behaviorId, onClose }: BehaviorDetailDrawerProps) {
  const { data: detail, isLoading, isError } = useBehaviorDetailQuery(
    caseId,
    behaviorId || ''
  );

  if (!behaviorId) return null;

  return (
    <>
      {/* Backdrop */}
      <div 
        className="fixed inset-0 bg-background/80 backdrop-blur-sm z-40 transition-opacity"
        onClick={onClose}
      />
      
      {/* Drawer */}
      <div className="fixed inset-y-0 right-0 w-full max-w-2xl bg-surface/95 backdrop-blur-xl border-l border-border-subtle/50 shadow-[0_0_40px_rgba(0,0,0,0.5)] z-50 flex flex-col transform transition-transform duration-300">
        
        {/* Header */}
        <div className="flex items-center justify-between p-5 border-b border-border-subtle/40 bg-surface-elevated/40">
          <h2 className="text-sm font-bold uppercase tracking-widest text-primary flex items-center gap-2">
            <Activity className="w-4 h-4 text-accent" />
            Behavior Intelligence
          </h2>
          <button 
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-surface-elevated hover:text-accent text-secondary transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-8 space-y-10">
          {isLoading ? (
            <div className="flex items-center justify-center h-48">
              <Spinner size={32} />
            </div>
          ) : isError || !detail ? (
            <div className="text-center text-red-400 p-4 bg-red-500/10 rounded-xl border border-red-500/20 shadow-[0_0_15px_rgba(239,68,68,0.1)]">
              Failed to load behavior details.
            </div>
          ) : (
            <>
              {/* Overview Section */}
              <section className="space-y-6">
                <div className="flex flex-col gap-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className={`px-3 py-1 rounded-md border text-[10px] font-bold uppercase tracking-widest shadow-sm ${SEVERITY_COLORS[detail.severity?.toLowerCase()] || SEVERITY_COLORS.info}`}>
                      {detail.severity || 'UNKNOWN'}
                    </span>
                    <span className="px-3 py-1 rounded-md border border-border-subtle/50 bg-background/50 text-[10px] font-mono text-secondary uppercase tracking-wider">
                      {detail.category ? detail.category.replace(/_/g, ' ') : 'Uncategorized'}
                    </span>
                    {detail.confidence !== null && (
                      <span className="px-3 py-1 rounded-md border border-accent/20 bg-accent/10 text-[10px] font-bold text-accent uppercase tracking-wider flex items-center gap-1.5 shadow-[0_0_8px_rgba(59,130,246,0.15)]">
                        <Activity className="w-3 h-3" />
                        {Math.round(detail.confidence * 100)}% Confidence
                      </span>
                    )}
                  </div>
                  
                  <h1 className="text-3xl font-extrabold text-transparent bg-clip-text bg-gradient-to-br from-primary via-primary/90 to-accent">
                    {detail.name}
                  </h1>
                </div>

                {detail.description && (
                  <div className="relative p-5 rounded-xl bg-surface/40 border border-border-subtle/40 text-sm text-primary/90 leading-relaxed shadow-inner">
                    <div className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-accent/60 to-transparent rounded-l-xl opacity-80" />
                    {detail.description}
                  </div>
                )}
                
                <div className="flex items-center gap-2 text-xs font-mono text-muted bg-background/30 p-2 rounded-lg border border-border-subtle/30 w-fit">
                  <Clock className="w-3.5 h-3.5 text-accent/60" />
                  <span>
                    Observed: {detail.first_observed ? new Date(detail.first_observed).toLocaleString() : 'N/A'} 
                    <span className="mx-2 text-border-subtle">|</span>
                    {detail.last_observed ? new Date(detail.last_observed).toLocaleString() : 'N/A'}
                  </span>
                </div>
              </section>

              {/* Associated Entities */}
              <section className="space-y-3">
                <div className="flex items-center gap-2 text-primary font-semibold border-b border-border-subtle pb-2">
                  <Fingerprint className="w-4 h-4" />
                  <h3>Associated Entities ({detail.associated_entities?.length || 0})</h3>
                </div>
                {detail.associated_entities?.length > 0 ? (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {detail.associated_entities.map(ent => (
                      <div key={ent.entity_id} className="p-3 rounded border border-border-subtle bg-surface-elevated/20 flex flex-col gap-1">
                        <span className="text-xs font-medium text-muted uppercase">{ent.entity_type}</span>
                        <span className="text-sm text-primary font-mono truncate" title={ent.name}>{ent.name}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted italic">No associated entities identified.</p>
                )}
              </section>

              {/* Related Timeline Events */}
              <section className="space-y-3">
                <div className="flex items-center gap-2 text-primary font-semibold border-b border-border-subtle pb-2">
                  <List className="w-4 h-4" />
                  <h3>Timeline Events ({detail.related_timeline_events?.length || 0})</h3>
                </div>
                {detail.related_timeline_events?.length > 0 ? (
                  <div className="space-y-3 relative before:absolute before:inset-y-0 before:left-2.5 before:w-px before:bg-border-subtle">
                    {detail.related_timeline_events.map((evt) => (
                      <div key={evt.timeline_event_id} className="relative pl-8">
                        <div className="absolute left-1.5 top-1.5 w-2.5 h-2.5 rounded-full bg-primary ring-4 ring-background" />
                        <div className="p-3 rounded border border-border-subtle bg-surface-elevated/20">
                          <div className="flex justify-between items-start gap-2 mb-1">
                            <span className="text-sm font-medium text-primary">{evt.title || evt.event_type}</span>
                            <span className="text-xs text-muted whitespace-nowrap">{new Date(evt.event_timestamp).toLocaleTimeString()}</span>
                          </div>
                          {evt.description && <p className="text-xs text-secondary">{evt.description}</p>}
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted italic">No supporting timeline events found.</p>
                )}
              </section>

              {/* MITRE Techniques */}
              <section className="space-y-3">
                <div className="flex items-center gap-2 text-primary font-semibold border-b border-border-subtle pb-2">
                  <Shield className="w-4 h-4" />
                  <h3>MITRE ATT&CK ({detail.related_mitre_techniques?.length || 0})</h3>
                </div>
                {detail.related_mitre_techniques?.length > 0 ? (
                  <div className="space-y-2">
                    {detail.related_mitre_techniques.map(mitre => (
                      <div key={mitre.mitre_mapping_id} className="p-3 rounded border border-border-subtle bg-surface-elevated/20 flex flex-col gap-1">
                        <div className="flex items-center gap-2">
                          <span className="text-xs font-bold text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded">{mitre.technique_id}</span>
                          <span className="text-sm font-medium text-primary">{mitre.technique_name}</span>
                        </div>
                        <span className="text-xs text-muted">{mitre.tactic_name || mitre.tactic_id}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted italic">No MITRE techniques mapped.</p>
                )}
              </section>

              {/* Relationships */}
              <section className="space-y-3">
                <div className="flex items-center gap-2 text-primary font-semibold border-b border-border-subtle pb-2">
                  <GitMerge className="w-4 h-4" />
                  <h3>Relationships ({detail.related_relationships?.length || 0})</h3>
                </div>
                {detail.related_relationships?.length > 0 ? (
                  <div className="space-y-2">
                    {detail.related_relationships.map(rel => (
                      <div key={rel.relationship_id} className="p-3 rounded border border-border-subtle bg-surface-elevated/20 text-sm flex items-center justify-between">
                        <span className="text-secondary font-mono truncate w-1/3 text-right">{rel.source_entity_id.slice(0,8)}</span>
                        <span className="text-xs font-medium text-primary bg-surface-elevated px-2 py-0.5 rounded-full border border-border-subtle mx-2">
                          {rel.relationship_type.replace(/_/g, ' ')}
                        </span>
                        <span className="text-secondary font-mono truncate w-1/3">{rel.target_entity_id.slice(0,8)}</span>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted italic">No derived relationships.</p>
                )}
              </section>

              {/* Raw Findings Data */}
              <section className="space-y-3">
                <div className="flex items-center gap-2 text-primary font-semibold border-b border-border-subtle pb-2">
                  <ExternalLink className="w-4 h-4" />
                  <h3>Evidence / Findings Data</h3>
                </div>
                {detail.related_findings?.length > 0 ? (
                  <div className="space-y-3">
                    {detail.related_findings.map((f, idx) => (
                      <div key={idx} className="p-3 rounded border border-border-subtle bg-[#0d1117] overflow-x-auto">
                        <pre className="text-[11px] text-slate-300 font-mono leading-relaxed">
                          {JSON.stringify(f, null, 2)}
                        </pre>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-sm text-muted italic">No raw finding evidence available.</p>
                )}
              </section>
            </>
          )}
        </div>
        
        {/* Footer Actions */}
        <div className="p-4 border-t border-border-subtle bg-surface-base flex justify-end gap-3">
          <button
            disabled={!detail}
            className="px-4 py-2 text-sm font-medium rounded-md border border-border-subtle bg-surface-elevated hover:bg-surface-elevated/80 text-primary transition-colors disabled:opacity-50"
          >
            Find in Timeline
          </button>
          <button
            disabled={!detail || detail.associated_entities?.length === 0}
            className="px-4 py-2 text-sm font-medium rounded-md border border-blue-500/50 bg-blue-500/10 hover:bg-blue-500/20 text-blue-400 transition-colors disabled:opacity-50"
          >
            View on Graph
          </button>
        </div>
      </div>
    </>
  );
}
