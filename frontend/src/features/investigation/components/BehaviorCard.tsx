import { ShieldAlert, Activity, ChevronRight, Clock } from 'lucide-react';
import type { BehaviorResponse } from '../types';

interface BehaviorCardProps {
  behavior: BehaviorResponse;
  onClick: () => void;
  selected?: boolean;
}

const SEVERITY_GRADIENTS: Record<string, string> = {
  critical: 'from-red-500/20 via-red-500/5 to-transparent',
  high: 'from-orange-500/20 via-orange-500/5 to-transparent',
  medium: 'from-yellow-500/20 via-yellow-500/5 to-transparent',
  low: 'from-blue-500/20 via-blue-500/5 to-transparent',
  info: 'from-slate-500/20 via-slate-500/5 to-transparent',
};

const SEVERITY_BORDER: Record<string, string> = {
  critical: 'border-l-red-500',
  high: 'border-l-orange-500',
  medium: 'border-l-yellow-500',
  low: 'border-l-blue-500',
  info: 'border-l-slate-500',
};

const SEVERITY_BADGE_STYLES: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30 shadow-[0_0_8px_rgba(239,68,68,0.2)]',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30 shadow-[0_0_8px_rgba(249,115,22,0.2)]',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30 shadow-[0_0_8px_rgba(234,179,8,0.2)]',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30 shadow-[0_0_8px_rgba(59,130,246,0.2)]',
  info: 'bg-slate-500/20 text-slate-400 border-slate-500/30 shadow-[0_0_8px_rgba(100,116,139,0.2)]',
};

function formatDuration(start?: string | null, end?: string | null): string {
  if (!start || !end) return 'Observation window pending';
  const diffSec = Math.round((new Date(end).getTime() - new Date(start).getTime()) / 1000);
  if (diffSec < 60) return `${diffSec}s`;
  if (diffSec < 3600) return `${Math.round(diffSec / 60)}m`;
  if (diffSec < 86400) return `${Math.round(diffSec / 3600)}h`;
  return `${Math.round(diffSec / 86400)}d`;
}

export function BehaviorCard({ behavior, onClick, selected }: BehaviorCardProps) {
  const sevKey = behavior.severity?.toLowerCase() || 'info';
  const bgGradient = SEVERITY_GRADIENTS[sevKey] || SEVERITY_GRADIENTS.info;
  const leftBorder = SEVERITY_BORDER[sevKey] || SEVERITY_BORDER.info;
  const badgeStyle = SEVERITY_BADGE_STYLES[sevKey] || SEVERITY_BADGE_STYLES.info;
  
  const confidence = behavior.confidence ? Math.round(behavior.confidence * 100) : 0;
  
  // Optional extension fields
  const hasCounts = 'related_entity_count' in behavior;
  const entityCount = (behavior as any).related_entity_count;
  const findingCount = (behavior as any).related_finding_count;
  const mitreCount = (behavior as any).mitre_count;

  return (
    <div
      onClick={onClick}
      className={`relative mb-3 overflow-hidden rounded-xl border border-border-subtle/50 bg-surface/30 backdrop-blur-sm cursor-pointer transition-all duration-300 group hover:-translate-y-0.5 hover:shadow-lg hover:border-accent/40 ${
        selected ? 'ring-2 ring-accent/50 bg-surface-elevated/40' : ''
      }`}
    >
      {/* Background Gradient */}
      <div className={`absolute inset-0 bg-gradient-to-r ${bgGradient} opacity-30 group-hover:opacity-50 transition-opacity duration-300 pointer-events-none`} />
      
      {/* Left indicator line */}
      <div className={`absolute left-0 top-0 bottom-0 w-1 ${leftBorder} opacity-80`} />

      <div className="relative p-5 flex flex-col md:flex-row md:items-start justify-between gap-6 pl-6">
        {/* Left: Main Details */}
        <div className="flex-1 min-w-0 space-y-3">
          <div className="flex items-center gap-3">
            <span className={`inline-flex items-center rounded border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider flex-shrink-0 ${badgeStyle}`}>
              {behavior.severity || 'UNKNOWN'}
            </span>
            <span className="text-xs font-mono px-2 py-0.5 rounded bg-background/50 border border-border-subtle/50 text-secondary truncate flex-shrink-0">
              {behavior.category ? behavior.category.replace(/_/g, ' ') : 'Uncategorized'}
            </span>
          </div>
          
          <h3 className="text-lg font-bold text-primary truncate group-hover:text-accent transition-colors" title={behavior.name}>
            {behavior.name}
          </h3>
          
          {behavior.description && (
            <p className="text-sm text-primary/80 line-clamp-2 leading-relaxed">
              {behavior.description}
            </p>
          )}
          
          {/* Metadata Row */}
          <div className="flex flex-wrap items-center gap-4 pt-1">
            <div className="flex items-center gap-1.5 text-xs text-muted font-medium bg-surface/50 px-2 py-1 rounded-md border border-border-subtle/30">
              <Clock className="w-3.5 h-3.5 text-accent/70" />
              <span>{formatDuration(behavior.first_observed, behavior.last_observed)}</span>
            </div>
            
            {hasCounts && (
              <>
                <div className="flex items-center gap-1.5 text-xs text-muted bg-surface/50 px-2 py-1 rounded-md border border-border-subtle/30">
                  <Activity className="w-3.5 h-3.5 text-green-400/70" />
                  <span>{entityCount ?? 0} entities</span>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-muted bg-surface/50 px-2 py-1 rounded-md border border-border-subtle/30">
                  <ShieldAlert className="w-3.5 h-3.5 text-red-400/70" />
                  <span>{findingCount ?? 0} findings, {mitreCount ?? 0} MITRE</span>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Right: Confidence & Action */}
        <div className="flex flex-col items-end gap-4 flex-shrink-0 min-w-[140px]">
          <div className="flex flex-col items-end w-full">
            <div className="flex items-center justify-between w-full mb-1.5">
              <span className="text-[10px] text-muted uppercase tracking-widest font-bold">Confidence</span>
              <span className="text-sm font-bold text-primary">{confidence}%</span>
            </div>
            <div className="w-full h-1.5 bg-background rounded-full overflow-hidden border border-border-subtle/50">
              <div 
                className="h-full bg-gradient-to-r from-accent/50 to-accent rounded-full shadow-[0_0_8px_rgba(59,130,246,0.6)]" 
                style={{ width: `${confidence}%` }}
              />
            </div>
          </div>
          
          <div className="mt-auto opacity-0 translate-x-2 group-hover:opacity-100 group-hover:translate-x-0 transition-all duration-300">
            <span className="flex items-center gap-1 text-xs text-accent font-bold bg-accent/10 px-3 py-1.5 rounded-md border border-accent/20">
              Analyze <ChevronRight className="w-3.5 h-3.5" />
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
