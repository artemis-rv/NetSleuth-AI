
import { ShieldAlert, Activity, ChevronRight, Clock } from 'lucide-react';
import type { BehaviorResponse } from '../types';

interface BehaviorCardProps {
  behavior: BehaviorResponse;
  onClick: () => void;
  selected?: boolean;
}

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'border-l-red-500 bg-red-500/5 hover:bg-red-500/10 text-red-400',
  high: 'border-l-orange-500 bg-orange-500/5 hover:bg-orange-500/10 text-orange-400',
  medium: 'border-l-yellow-500 bg-yellow-500/5 hover:bg-yellow-500/10 text-yellow-400',
  low: 'border-l-blue-500 bg-blue-500/5 hover:bg-blue-500/10 text-blue-400',
  info: 'border-l-slate-500 bg-slate-500/5 hover:bg-slate-500/10 text-slate-400',
};

const SEVERITY_BADGE_STYLES: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  info: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
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
  const cardStyle = SEVERITY_STYLES[sevKey] || SEVERITY_STYLES.info;
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
      className={`relative p-4 border-y border-r border-border-subtle border-l-4 cursor-pointer transition-all duration-200 group ${cardStyle} ${
        selected ? 'ring-1 ring-inset ring-primary/20 bg-surface-elevated/40' : ''
      }`}
    >
      <div className="flex flex-col md:flex-row md:items-start justify-between gap-4">
        {/* Left: Main Details */}
        <div className="flex-1 min-w-0 space-y-2">
          <div className="flex items-center gap-3">
            <span className={`inline-flex items-center rounded border px-2 py-0.5 text-[11px] font-bold uppercase tracking-wider flex-shrink-0 ${badgeStyle}`}>
              {behavior.severity || 'UNKNOWN'}
            </span>
            <span className="text-xs font-medium px-2 py-0.5 rounded bg-surface-elevated border border-border-subtle text-secondary truncate flex-shrink-0">
              {behavior.category ? behavior.category.replace(/_/g, ' ') : 'Uncategorized'}
            </span>
          </div>
          
          <h3 className="text-base font-semibold text-primary truncate" title={behavior.name}>
            {behavior.name}
          </h3>
          
          {behavior.description && (
            <p className="text-sm text-secondary line-clamp-2 leading-relaxed">
              {behavior.description}
            </p>
          )}
          
          {/* Metadata Row */}
          <div className="flex flex-wrap items-center gap-4 pt-2">
            <div className="flex items-center gap-1.5 text-xs text-muted">
              <Clock className="w-3.5 h-3.5" />
              <span>{formatDuration(behavior.first_observed, behavior.last_observed)} duration</span>
            </div>
            
            {hasCounts && (
              <>
                <div className="flex items-center gap-1.5 text-xs text-muted border-l border-border-subtle pl-4">
                  <Activity className="w-3.5 h-3.5" />
                  <span>{entityCount ?? 0} entities</span>
                </div>
                <div className="flex items-center gap-1.5 text-xs text-muted border-l border-border-subtle pl-4">
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>{findingCount ?? 0} findings, {mitreCount ?? 0} MITRE</span>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Right: Confidence & Action */}
        <div className="flex flex-col items-end gap-3 flex-shrink-0">
          <div className="flex flex-col items-end">
            <span className="text-xs text-muted mb-1 uppercase tracking-widest font-semibold">Confidence</span>
            <div className="flex items-center gap-2">
              <span className="text-sm font-bold text-primary">{confidence}%</span>
              <div className="w-20 h-1.5 bg-background rounded-full overflow-hidden border border-border-subtle">
                <div 
                  className="h-full bg-primary/80 rounded-full" 
                  style={{ width: `${confidence}%` }}
                />
              </div>
            </div>
          </div>
          
          <div className="mt-auto opacity-0 group-hover:opacity-100 transition-opacity">
            <span className="flex items-center gap-1 text-xs text-primary font-medium bg-surface-elevated px-2 py-1 rounded border border-border-subtle">
              View details <ChevronRight className="w-3.5 h-3.5" />
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
