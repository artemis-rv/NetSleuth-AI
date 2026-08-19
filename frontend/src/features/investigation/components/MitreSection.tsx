import { AlertCircle, Target, Shield, Activity, Link as LinkIcon, FileText, Clock, ExternalLink } from 'lucide-react';
import { useMitreQuery, useTimelineQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import { Card, CardContent } from '../../../components/ui/Card';
import type { MitreMappingResponse } from '../types';
import { useSearchParams } from 'react-router-dom';

function confidenceColor(conf: number | null): string {
  if (conf === null) return 'bg-slate-700/60 border-slate-600/40 text-slate-400';
  if (conf >= 0.8) return 'bg-red-500/15 border-red-500/30 text-red-400';
  if (conf >= 0.6) return 'bg-orange-500/15 border-orange-500/30 text-orange-400';
  if (conf >= 0.4) return 'bg-yellow-500/15 border-yellow-500/30 text-yellow-400';
  return 'bg-blue-500/15 border-blue-500/30 text-blue-400';
}

function formatDate(isoStr: string) {
  return new Date(isoStr).toLocaleString(undefined, {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

function formatShortId(id: string) {
  return id.split('-')[0];
}

interface MitreSectionProps {
  caseId: string;
}

export function MitreSection({ caseId }: MitreSectionProps) {
  const [searchParams, setSearchParams] = useSearchParams();
  const { data, isLoading, isError, error } = useMitreQuery(caseId, { page: 1, page_size: 100 });
  const { data: timelineData, isLoading: timelineLoading } = useTimelineQuery(caseId, { page: 1, page_size: 100 });

  if (isLoading || timelineLoading) {
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
        title="No ATT&CK mappings available"
        description="No ATT&CK technique mappings have been produced for this investigation yet."
      />
    );
  }

  // Calculate Summary Metrics
  const uniqueTactics = new Set(data.items.map((m) => m.tactic_name || m.tactic_id));
  const uniqueTechniques = new Set(data.items.map((m) => m.technique_id));
  const uniqueFindings = new Set(data.items.flatMap((m) => m.finding_ids || []));
  const evidenceLinked = data.items.filter((m) => m.finding_ids && m.finding_ids.length > 0).length;

  // Group by tactic
  const tacticMap = new Map<string, { tactic_name: string; techniques: MitreMappingResponse[] }>();

  for (const mapping of data.items) {
    const tacticKey = mapping.tactic_name || mapping.tactic_id;
    if (!tacticMap.has(tacticKey)) {
      tacticMap.set(tacticKey, {
        tactic_name: tacticKey,
        techniques: [],
      });
    }
    tacticMap.get(tacticKey)!.techniques.push(mapping);
  }

  const tactics = Array.from(tacticMap.values()).sort((a, b) =>
    a.tactic_name.localeCompare(b.tactic_name)
  );

  return (
    <div className="space-y-8 pb-10">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-primary flex items-center gap-2">
          <Target className="h-5 w-5 text-accent" />
          MITRE ATT&CK®
        </h2>
        <p className="text-sm text-muted mt-1">
          Map evidence-backed observed behaviors to MITRE ATT&CK tactics and techniques.
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-surface border-border-subtle">
          <CardContent className="p-4 flex flex-col">
            <span className="text-xs font-semibold uppercase text-muted tracking-wider mb-2">Tactics Observed</span>
            <span className="text-2xl font-bold text-primary">{uniqueTactics.size}</span>
          </CardContent>
        </Card>
        <Card className="bg-surface border-border-subtle">
          <CardContent className="p-4 flex flex-col">
            <span className="text-xs font-semibold uppercase text-muted tracking-wider mb-2">Techniques Mapped</span>
            <span className="text-2xl font-bold text-primary">{uniqueTechniques.size}</span>
          </CardContent>
        </Card>
        <Card className="bg-surface border-border-subtle">
          <CardContent className="p-4 flex flex-col">
            <span className="text-xs font-semibold uppercase text-muted tracking-wider mb-2">Findings Mapped</span>
            <span className="text-2xl font-bold text-primary">{uniqueFindings.size}</span>
          </CardContent>
        </Card>
        <Card className="bg-surface border-border-subtle">
          <CardContent className="p-4 flex flex-col">
            <span className="text-xs font-semibold uppercase text-muted tracking-wider mb-2">Evidence-Linked Mappings</span>
            <span className="text-2xl font-bold text-primary">{evidenceLinked}</span>
          </CardContent>
        </Card>
      </div>

      {/* Tactic Grouping (Progression) & Technique Cards */}
      <div className="space-y-6">
        <h3 className="text-sm font-semibold uppercase text-muted tracking-widest border-b border-border-subtle pb-2">
          Tactic Progression
        </h3>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
          {tactics.map((tactic) => (
            <div key={tactic.tactic_name} className="flex flex-col gap-3">
              <h4 className="text-sm font-bold text-primary uppercase tracking-wider mb-1 flex items-center gap-2">
                <Shield className="h-4 w-4 text-accent" />
                {tactic.tactic_name}
              </h4>
              
              {tactic.techniques.map((tech) => (
                <div key={tech.mitre_mapping_id} className="bg-surface-elevated border border-border-subtle rounded-lg p-4 flex flex-col gap-3 transition-all hover:border-accent/40">
                  <div className="flex justify-between items-start">
                    <div>
                      <span className="text-xs font-mono font-bold text-accent px-1.5 py-0.5 bg-accent/10 rounded">
                        {tech.technique_id}
                      </span>
                      <p className="text-sm font-medium text-primary mt-1.5 leading-snug">
                        {tech.technique_name}
                      </p>
                    </div>
                    {tech.confidence !== null && (
                      <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${confidenceColor(tech.confidence)}`}>
                        {Math.round(tech.confidence * 100)}% CONFIDENCE
                      </span>
                    )}
                  </div>
                  
                  {tech.finding_ids && tech.finding_ids.length > 0 && (
                    <div className="text-[11px] text-muted flex items-center gap-3">
                      <span 
                        className="flex items-center gap-1.5 hover:text-accent cursor-pointer transition-colors"
                        onClick={() => {
                          searchParams.set('finding', tech.finding_ids![0]);
                          setSearchParams(searchParams);
                        }}
                      >
                        <Activity className="h-3 w-3" />
                        {tech.finding_ids.length} finding{tech.finding_ids.length !== 1 ? 's' : ''}
                      </span>
                      <span 
                        className="flex items-center gap-1.5 hover:text-accent cursor-pointer transition-colors"
                        onClick={() => {
                          searchParams.set('finding', tech.finding_ids![0]);
                          setSearchParams(searchParams);
                        }}
                      >
                        <LinkIcon className="h-3 w-3" />
                        {tech.finding_ids.length} evidence ref{tech.finding_ids.length !== 1 ? 's' : ''}
                      </span>
                    </div>
                  )}
                  
                  {tech.rationale && (
                    <div className="bg-background/50 rounded px-3 py-2 text-xs text-secondary mt-1 italic border-l-2 border-accent/40">
                      "{tech.rationale}"
                    </div>
                  )}
                </div>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Technique Mappings Table */}
      <div className="space-y-4 pt-4">
        <h3 className="text-sm font-semibold uppercase text-muted tracking-widest border-b border-border-subtle pb-2">
          Technique Mappings
        </h3>
        
        <div className="border border-border-subtle rounded-lg overflow-hidden bg-surface">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="bg-surface-elevated border-b border-border-subtle text-xs uppercase text-muted">
                  <th className="px-4 py-3 font-semibold">Tactic</th>
                  <th className="px-4 py-3 font-semibold">Technique</th>
                  <th className="px-4 py-3 font-semibold">ID</th>
                  <th className="px-4 py-3 font-semibold">Confidence</th>
                  <th className="px-4 py-3 font-semibold">Related Finding</th>
                  <th className="px-4 py-3 font-semibold">Timeline Event</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {data.items.map((m) => {
                  // Find associated timeline event
                  const relatedEvent = m.finding_ids && m.finding_ids.length > 0 
                    ? timelineData?.items.find(e => e.finding_id && m.finding_ids!.includes(e.finding_id))
                    : undefined;

                  return (
                    <tr key={m.mitre_mapping_id} className="hover:bg-surface-elevated/50 transition-colors border-b border-border-subtle last:border-0">
                      <td className="px-4 py-3 text-secondary text-xs uppercase tracking-wider">
                        {m.tactic_name || m.tactic_id}
                      </td>
                      <td className="px-4 py-3 font-medium text-primary text-xs">
                        {m.technique_name}
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[11px] font-mono font-bold text-accent px-1.5 py-0.5 bg-accent/10 rounded">
                          {m.technique_id}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        {m.confidence !== null ? (
                          <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${confidenceColor(m.confidence)}`}>
                            {Math.round(m.confidence * 100)}%
                          </span>
                        ) : (
                          <span className="text-muted text-xs">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {m.finding_ids && m.finding_ids.length > 0 ? (
                          <div className="flex flex-col gap-1">
                            {m.finding_ids.map((fId: string) => (
                              <div key={fId} className="flex items-center gap-1.5">
                                <FileText className="h-3 w-3 text-muted" />
                                <span 
                                  className="text-xs text-secondary font-mono hover:text-accent cursor-pointer transition-colors flex items-center gap-1"
                                  onClick={() => {
                                    searchParams.set('finding', fId);
                                    setSearchParams(searchParams);
                                  }}
                                >
                                  {formatShortId(fId)}
                                  <ExternalLink className="h-2.5 w-2.5" />
                                </span>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <span className="text-muted text-xs">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {relatedEvent ? (
                          <div className="flex flex-col gap-1">
                            <span className="text-[11px] text-muted flex items-center gap-1 font-mono">
                              <Clock className="h-3 w-3" />
                              {formatDate(relatedEvent.event_timestamp)}
                            </span>
                            <span className="text-xs text-secondary truncate max-w-[200px]" title={relatedEvent.description ?? undefined}>
                              {relatedEvent.description}
                            </span>
                          </div>
                        ) : (
                          <span className="text-muted text-xs">—</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
