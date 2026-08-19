import { useState } from 'react';
import { ChevronDown, ChevronRight, Server, Globe, ShieldAlert, ArrowUpRight, ArrowDownLeft } from 'lucide-react';
import type { NetworkEndpointContext } from '../types';
import { ExpandedEndpointPanel } from './ExpandedEndpointPanel';

interface EndpointContextRowProps {
  endpoint: NetworkEndpointContext;
  onSelectFlow: (flowId: string) => void;
  onSelectFinding: (findingId: string) => void;
}

export function EndpointContextRow({ endpoint, onSelectFlow, onSelectFinding }: EndpointContextRowProps) {
  const [expanded, setExpanded] = useState(false);

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  const isPrivate = endpoint.network_scope === 'PRIVATE/INTERNAL';
  const badgeColor = isPrivate 
    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' 
    : 'bg-amber-500/10 text-amber-400 border-amber-500/30';

  return (
    <div className="border border-border-subtle rounded-lg overflow-hidden bg-surface transition-all">
      {/* Dense Row Header */}
      <div 
        className="flex flex-wrap items-center justify-between p-3 cursor-pointer hover:bg-surface-elevated transition-colors gap-3"
        onClick={() => setExpanded(!expanded)}
      >
        {/* Left: Icon, IP, Scope, Role, Protocols */}
        <div className="flex items-center gap-3 flex-wrap">
          {expanded ? <ChevronDown className="h-4 w-4 text-muted" /> : <ChevronRight className="h-4 w-4 text-muted" />}
          {isPrivate ? <Server className="h-4 w-4 text-emerald-400" /> : <Globe className="h-4 w-4 text-amber-400" />}
          
          <div className="flex flex-col">
            <div className="flex items-center gap-2">
              <span className="font-mono text-sm font-bold text-primary">{endpoint.ip}</span>
              <span className={`text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded border ${badgeColor}`}>
                {endpoint.network_scope}
              </span>
              <span className="text-[10px] font-mono bg-surface-elevated border border-border-subtle px-1.5 py-0.5 rounded text-muted">
                {endpoint.role}
              </span>
            </div>
            {endpoint.associated_domain && (
              <span className="font-mono text-[11px] text-accent font-medium truncate max-w-xs">
                {endpoint.associated_domain}
              </span>
            )}
          </div>

          {/* Protocols & Ports */}
          <div className="flex items-center gap-1 font-mono text-[11px] text-secondary bg-surface-elevated border border-border-subtle px-2 py-0.5 rounded">
            <span>{endpoint.communication.protocols.join(' · ') || 'TCP'}</span>
            {endpoint.communication.destination_ports.length > 0 && (
              <span className="text-muted">:{endpoint.communication.destination_ports.join(',')}</span>
            )}
          </div>
        </div>

        {/* Center: Traffic Breakdown OUT / IN */}
        <div className="flex items-center gap-4 font-mono text-xs">
          <div className="flex items-center gap-1 text-emerald-400">
            <ArrowUpRight className="h-3.5 w-3.5" />
            <span>{formatBytes(endpoint.traffic.bytes_sent)} OUT</span>
          </div>
          <div className="flex items-center gap-1 text-amber-400">
            <ArrowDownLeft className="h-3.5 w-3.5" />
            <span>{formatBytes(endpoint.traffic.bytes_received)} IN</span>
          </div>
        </div>

        {/* Right: Flow count & M2 Risk Badge */}
        <div className="flex items-center gap-3">
          {endpoint.m2_findings.finding_count > 0 && (
            <span className="text-[10px] font-bold bg-red-500/10 text-red-400 border border-red-500/30 px-2 py-1 rounded flex items-center gap-1">
              <ShieldAlert className="h-3.5 w-3.5" />
              {endpoint.m2_findings.highest_severity} ({endpoint.m2_findings.finding_count})
            </span>
          )}

          <span className="text-xs font-mono bg-surface-elevated border border-border-subtle px-2.5 py-1 rounded text-muted">
            {endpoint.communication.total_flows} flows
          </span>
        </div>
      </div>

      {/* Expanded Forensic Context Panel */}
      {expanded && (
        <ExpandedEndpointPanel
          endpoint={endpoint}
          onSelectFlow={onSelectFlow}
          onSelectFinding={onSelectFinding}
        />
      )}
    </div>
  );
}
