import { AlertCircle, Target, Shield, Activity, Link as LinkIcon, FileText, Clock, ExternalLink } from 'lucide-react';
import { useMitreQuery, useTimelineQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import { Card, CardContent } from '../../../components/ui/Card';
import type { MitreMappingResponse } from '../types';
import { useSearchParams } from 'react-router-dom';

function confidenceColor(conf: number | null): string {
  if (conf === null) return 'bg-slate-700/20 border-slate-600/40 text-slate-400 shadow-sm';
  if (conf >= 0.8) return 'bg-red-500/10 border-red-500/30 text-red-400 shadow-[0_0_8px_rgba(239,68,68,0.15)]';
  if (conf >= 0.6) return 'bg-orange-500/10 border-orange-500/30 text-orange-400 shadow-[0_0_8px_rgba(249,115,22,0.15)]';
  if (conf >= 0.4) return 'bg-yellow-500/10 border-yellow-500/30 text-yellow-400 shadow-[0_0_8px_rgba(234,179,8,0.15)]';
  return 'bg-blue-500/10 border-blue-500/30 text-blue-400 shadow-[0_0_8px_rgba(59,130,246,0.15)]';
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
        <Spinner size={32} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex items-center gap-2 p-4 rounded-xl border border-red-500/30 bg-red-500/5 text-red-400 text-sm shadow-[0_0_15px_rgba(239,68,68,0.1)]">
        <AlertCircle className="h-5 w-5 flex-shrink-0" aria-hidden="true" />
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
    <div className="space-y-10 pb-12">
      {/* Header */}
      <div className="flex flex-col gap-2">
        <h2 className="text-2xl font-extrabold text-transparent bg-clip-text bg-gradient-to-r from-primary to-accent flex items-center gap-2 w-fit">
          <Target className="h-6 w-6 text-accent drop-shadow-[0_0_8px_rgba(59,130,246,0.6)]" />
          MITRE ATT&CK®
        </h2>
        <p className="text-sm text-secondary font-medium">
          Map evidence-backed observed behaviors to MITRE ATT&CK tactics and techniques.
        </p>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-surface/40 backdrop-blur-md border-border-subtle/50 hover:border-accent/30 transition-all duration-300 hover:shadow-[0_0_15px_rgba(59,130,246,0.1)] group">
          <CardContent className="p-5 flex flex-col items-center justify-center text-center">
            <span className="text-[10px] font-bold uppercase text-muted tracking-widest mb-2 group-hover:text-accent transition-colors">Tactics Observed</span>
            <span className="text-4xl font-extrabold text-primary">{uniqueTactics.size}</span>
          </CardContent>
        </Card>
        <Card className="bg-surface/40 backdrop-blur-md border-border-subtle/50 hover:border-accent/30 transition-all duration-300 hover:shadow-[0_0_15px_rgba(59,130,246,0.1)] group">
          <CardContent className="p-5 flex flex-col items-center justify-center text-center">
            <span className="text-[10px] font-bold uppercase text-muted tracking-widest mb-2 group-hover:text-accent transition-colors">Techniques Mapped</span>
            <span className="text-4xl font-extrabold text-primary">{uniqueTechniques.size}</span>
          </CardContent>
        </Card>
        <Card className="bg-surface/40 backdrop-blur-md border-border-subtle/50 hover:border-accent/30 transition-all duration-300 hover:shadow-[0_0_15px_rgba(59,130,246,0.1)] group">
          <CardContent className="p-5 flex flex-col items-center justify-center text-center">
            <span className="text-[10px] font-bold uppercase text-muted tracking-widest mb-2 group-hover:text-accent transition-colors">Findings Mapped</span>
            <span className="text-4xl font-extrabold text-primary">{uniqueFindings.size}</span>
          </CardContent>
        </Card>
        <Card className="bg-surface/40 backdrop-blur-md border-border-subtle/50 hover:border-accent/30 transition-all duration-300 hover:shadow-[0_0_15px_rgba(59,130,246,0.1)] group">
          <CardContent className="p-5 flex flex-col items-center justify-center text-center">
            <span className="text-[10px] font-bold uppercase text-muted tracking-widest mb-2 group-hover:text-accent transition-colors">Evidence Links</span>
            <span className="text-4xl font-extrabold text-primary">{evidenceLinked}</span>
          </CardContent>
        </Card>
      </div>

      {/* Tactic Grouping (Progression) & Technique Cards */}
      <div className="space-y-6">
        <div className="flex items-center gap-3 border-b border-border-subtle/40 pb-3">
          <div className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
          <h3 className="text-xs font-bold uppercase text-muted tracking-widest">
            Tactic Progression
          </h3>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
          {tactics.map((tactic) => (
            <div key={tactic.tactic_name} className="flex flex-col gap-4">
              <h4 className="text-[13px] font-extrabold text-primary uppercase tracking-widest flex items-center gap-2 bg-surface/50 p-2 rounded-lg border border-border-subtle/30 shadow-sm w-fit">
                <Shield className="h-4 w-4 text-accent" />
                {tactic.tactic_name}
              </h4>
              
              <div className="flex flex-col gap-3">
                {tactic.techniques.map((tech) => (
                  <div key={tech.mitre_mapping_id} className="relative bg-surface/40 backdrop-blur-sm border border-border-subtle/50 rounded-xl p-5 flex flex-col gap-3 transition-all duration-300 hover:border-accent/50 hover:shadow-[0_4px_20px_rgba(59,130,246,0.1)] group hover:-translate-y-0.5 overflow-hidden">
                    <div className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-accent to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
                    
                    <div className="flex justify-between items-start">
                      <div>
                        <span className="text-[11px] font-mono font-bold text-accent px-2 py-0.5 bg-accent/10 border border-accent/20 rounded-md shadow-sm">
                          {tech.technique_id}
                        </span>
                        <p className="text-sm font-bold text-primary mt-2 leading-snug group-hover:text-accent transition-colors">
                          {tech.technique_name}
                        </p>
                      </div>
                      {tech.confidence !== null && (
                        <span className={`text-[10px] font-bold px-2 py-1 rounded-md border flex-shrink-0 ${confidenceColor(tech.confidence)}`}>
                          {Math.round(tech.confidence * 100)}% CONF
                        </span>
                      )}
                    </div>
                    
                    {tech.finding_ids && tech.finding_ids.length > 0 && (
                      <div className="text-[11px] text-muted flex items-center gap-4 mt-1 font-medium">
                        <span 
                          className="flex items-center gap-1.5 hover:text-accent cursor-pointer transition-colors bg-background/50 px-2 py-1 rounded-md border border-border-subtle/40"
                          onClick={() => {
                            searchParams.set('finding', tech.finding_ids![0]);
                            setSearchParams(searchParams);
                          }}
                        >
                          <Activity className="h-3 w-3 text-green-400/80" />
                          {tech.finding_ids.length} finding{tech.finding_ids.length !== 1 ? 's' : ''}
                        </span>
                        <span 
                          className="flex items-center gap-1.5 hover:text-accent cursor-pointer transition-colors bg-background/50 px-2 py-1 rounded-md border border-border-subtle/40"
                          onClick={() => {
                            searchParams.set('finding', tech.finding_ids![0]);
                            setSearchParams(searchParams);
                          }}
                        >
                          <LinkIcon className="h-3 w-3 text-blue-400/80" />
                          {tech.finding_ids.length} ref{tech.finding_ids.length !== 1 ? 's' : ''}
                        </span>
                      </div>
                    )}
                    
                    {tech.rationale && (
                      <div className="bg-background/40 rounded-lg px-3 py-2.5 text-[11px] text-secondary mt-1 italic border-l-2 border-accent/30 leading-relaxed shadow-inner">
                        "{tech.rationale}"
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Technique Mappings Table */}
      <div className="space-y-4 pt-8">
        <div className="flex items-center gap-3 border-b border-border-subtle/40 pb-3">
          <div className="h-1.5 w-1.5 rounded-full bg-accent animate-pulse" />
          <h3 className="text-xs font-bold uppercase text-muted tracking-widest">
            Technique Mapping Matrix
          </h3>
        </div>
        
        <div className="border border-border-subtle/60 rounded-xl overflow-hidden bg-surface/30 backdrop-blur-sm shadow-sm">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse text-sm">
              <thead>
                <tr className="bg-surface-elevated/40 border-b border-border-subtle/60 text-[10px] uppercase tracking-widest text-muted font-bold">
                  <th className="px-5 py-4">Tactic</th>
                  <th className="px-5 py-4">Technique</th>
                  <th className="px-5 py-4">ID</th>
                  <th className="px-5 py-4">Confidence</th>
                  <th className="px-5 py-4">Related Finding</th>
                  <th className="px-5 py-4">Timeline Event</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/40">
                {data.items.map((m) => {
                  // Find associated timeline event
                  const relatedEvent = m.finding_ids && m.finding_ids.length > 0 
                    ? timelineData?.items.find(e => e.finding_id && m.finding_ids!.includes(e.finding_id))
                    : undefined;

                  return (
                    <tr key={m.mitre_mapping_id} className="hover:bg-surface-elevated/60 transition-colors border-b border-border-subtle/40 last:border-0 group">
                      <td className="px-5 py-4 text-secondary text-[11px] font-bold uppercase tracking-wider">
                        {m.tactic_name || m.tactic_id}
                      </td>
                      <td className="px-5 py-4 font-bold text-primary text-xs group-hover:text-accent transition-colors">
                        {m.technique_name}
                      </td>
                      <td className="px-5 py-4">
                        <span className="text-[11px] font-mono font-bold text-accent px-2 py-1 bg-accent/10 border border-accent/20 rounded-md shadow-sm">
                          {m.technique_id}
                        </span>
                      </td>
                      <td className="px-5 py-4">
                        {m.confidence !== null ? (
                          <span className={`text-[10px] font-bold px-2 py-1 rounded-md border flex-shrink-0 ${confidenceColor(m.confidence)}`}>
                            {Math.round(m.confidence * 100)}%
                          </span>
                        ) : (
                          <span className="text-muted text-xs">—</span>
                        )}
                      </td>
                      <td className="px-5 py-4">
                        {m.finding_ids && m.finding_ids.length > 0 ? (
                          <div className="flex flex-col gap-1.5">
                            {m.finding_ids.map((fId: string) => (
                              <div key={fId} className="flex items-center gap-1.5 bg-background/50 w-fit px-2 py-1 rounded border border-border-subtle/30">
                                <FileText className="h-3 w-3 text-accent/60" />
                                <span 
                                  className="text-[11px] text-secondary font-mono hover:text-accent cursor-pointer transition-colors flex items-center gap-1 font-bold"
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
                      <td className="px-5 py-4">
                        {relatedEvent ? (
                          <div className="flex flex-col gap-1.5">
                            <span className="text-[10px] text-muted flex items-center gap-1.5 font-mono bg-background/40 w-fit px-2 py-0.5 rounded border border-border-subtle/30">
                              <Clock className="h-3 w-3 text-accent/60" />
                              {formatDate(relatedEvent.event_timestamp)}
                            </span>
                            <span className="text-xs text-primary/80 font-medium truncate max-w-[200px]" title={relatedEvent.description ?? undefined}>
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
