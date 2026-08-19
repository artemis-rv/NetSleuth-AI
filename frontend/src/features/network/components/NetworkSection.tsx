import { useState, useMemo } from 'react';
import { AlertCircle, ChevronDown, ChevronRight, ChevronLeft, ShieldAlert, Globe, Server } from 'lucide-react';
import { useFlowsQuery, useNetworkIPEntitiesQuery } from '../hooks';
import { FlowRow } from './FlowRow';
import { FlowFilters } from './FlowFilters';
import { FlowDetailDrawer } from './FlowDetailDrawer';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { FlowListItem, FlowsFilters, IPEntityResponse } from '../types';

interface NetworkSectionProps {
  caseId: string;
}

export function NetworkSection({ caseId }: NetworkSectionProps) {
  const [filters, setFilters] = useState<FlowsFilters>({ page: 1, page_size: 50 });
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(null);

  const { data, isLoading, isError, error } = useFlowsQuery(caseId, filters);
  const { data: entitiesData } = useNetworkIPEntitiesQuery(caseId);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 50)) : 0;
  const currentPage = filters.page ?? 1;

  function handleRowClick(flow: FlowListItem) {
    setSelectedFlowId(flow.flow_id);
  }

  // Merge backend IPEntityResponse metadata with flows
  const groupedData = useMemo(() => {
    if (!data?.items) return [];

    const entitiesMap = new Map<string, IPEntityResponse>();
    if (entitiesData?.items) {
      entitiesData.items.forEach(e => entitiesMap.set(e.ip, e));
    }

    const ipMap = new Map<string, FlowListItem[]>();

    data.items.forEach(flow => {
      if (!ipMap.has(flow.src_ip)) ipMap.set(flow.src_ip, []);
      ipMap.get(flow.src_ip)!.push(flow);

      if (flow.dst_ip !== flow.src_ip) {
        if (!ipMap.has(flow.dst_ip)) ipMap.set(flow.dst_ip, []);
        ipMap.get(flow.dst_ip)!.push(flow);
      }
    });

    return Array.from(ipMap.entries())
      .map(([ip, flows]) => {
        const entityMeta = entitiesMap.get(ip);
        const incoming = flows.filter(f => f.dst_ip === ip);
        const outgoing = flows.filter(f => f.src_ip === ip);

        const protocols = Array.from(new Set(flows.map(f => f.protocol || f.service).filter(Boolean)));
        const protocolGroups = protocols.map(proto => ({
          name: proto?.toUpperCase() || 'UNKNOWN',
          flows: flows.filter(f => (f.protocol || f.service) === proto)
        }));

        const isPrivate = entityMeta?.classification === 'PRIVATE/INTERNAL';

        return {
          ip,
          classification: entityMeta?.classification || (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('172.16.') ? 'PRIVATE/INTERNAL' : 'PUBLIC/EXTERNAL'),
          role: entityMeta?.role || (incoming.length && outgoing.length ? 'BOTH' : outgoing.length ? 'SOURCE' : 'DESTINATION'),
          relatedDomains: entityMeta?.related_domains || [],
          services: entityMeta?.services || protocols.map(p => p.toUpperCase()),
          firstSeen: entityMeta?.first_seen || flows[0]?.timestamp,
          lastSeen: entityMeta?.last_seen || flows[flows.length - 1]?.timestamp,
          findingCount: entityMeta?.finding_count || 0,
          totalFlows: flows.length,
          isPrivate,
          categories: [
            { name: 'Incoming', flows: incoming },
            { name: 'Outgoing', flows: outgoing },
            ...protocolGroups
          ].filter(c => c.flows.length > 0)
        };
      })
      .sort((a, b) => b.totalFlows - a.totalFlows);

  }, [data, entitiesData]);

  const internalEndpoints = useMemo(() => groupedData.filter(g => g.isPrivate), [groupedData]);
  const externalEndpoints = useMemo(() => groupedData.filter(g => !g.isPrivate), [groupedData]);

  return (
    <div className="space-y-4">
      <FlowFilters filters={filters} onChange={setFilters} />

      {data && (
        <div className="flex items-center justify-between text-xs text-muted">
          <span>{data.total.toLocaleString()} flow{data.total !== 1 ? 's' : ''} captured</span>
          <div className="flex items-center gap-3 font-mono">
            <span className="text-emerald-400 font-medium">{internalEndpoints.length} Internal</span>
            <span className="text-amber-400 font-medium">{externalEndpoints.length} External</span>
          </div>
        </div>
      )}

      {isLoading && (
        <div className="flex items-center justify-center py-16">
          <Spinner size={28} />
        </div>
      )}

      {isError && (
        <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
          Failed to load network flows. {(error as Error)?.message}
        </div>
      )}

      {data && data.items.length === 0 && (
        <EmptyState
          title="No Flows"
          description="No network flows match the current filters for this investigation."
        />
      )}

      {data && data.items.length > 0 && (
        <div className="space-y-6">
          {/* Internal Endpoints */}
          {internalEndpoints.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-emerald-400 pb-1 border-b border-emerald-500/20">
                <Server className="h-3.5 w-3.5" />
                <span>Internal / Private Endpoints ({internalEndpoints.length})</span>
              </div>
              <div className="space-y-2">
                {internalEndpoints.map(group => (
                  <IPGroup key={group.ip} group={group} onRowClick={handleRowClick} />
                ))}
              </div>
            </div>
          )}

          {/* External Endpoints */}
          {externalEndpoints.length > 0 && (
            <div className="space-y-2">
              <div className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-amber-400 pb-1 border-b border-amber-500/20">
                <Globe className="h-3.5 w-3.5" />
                <span>External / Public Endpoints ({externalEndpoints.length})</span>
              </div>
              <div className="space-y-2">
                {externalEndpoints.map(group => (
                  <IPGroup key={group.ip} group={group} onRowClick={handleRowClick} />
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {data && data.items.length > 0 && totalPages > 1 && (
        <div className="flex items-center justify-between mt-4">
          <p className="text-xs text-muted">
            Page {currentPage} of {totalPages} · {data.total.toLocaleString()} total
          </p>
          <div className="flex items-center gap-1">
            <button
              id="flows-prev-page"
              onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
              disabled={currentPage <= 1}
              className="p-1 text-muted hover:text-primary disabled:opacity-30 transition-colors rounded hover:bg-surface-elevated"
            >
              <ChevronLeft className="h-4 w-4" />
            </button>
            <button
              id="flows-next-page"
              onClick={() => setFilters((f) => ({ ...f, page: Math.min(totalPages, currentPage + 1) }))}
              disabled={currentPage >= totalPages}
              className="p-1 text-muted hover:text-primary disabled:opacity-30 transition-colors rounded hover:bg-surface-elevated"
            >
              <ChevronRight className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}

      {selectedFlowId && (
        <FlowDetailDrawer
          flowId={selectedFlowId}
          onClose={() => setSelectedFlowId(null)}
        />
      )}
    </div>
  );
}

function IPGroup({ group, onRowClick }: { group: any, onRowClick: (flow: FlowListItem) => void }) {
  const [expanded, setExpanded] = useState(false);

  const isPrivate = group.classification === 'PRIVATE/INTERNAL';
  const badgeColor = isPrivate 
    ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30' 
    : 'bg-amber-500/10 text-amber-400 border-amber-500/30';

  return (
    <div className="border border-border-subtle rounded-lg overflow-hidden bg-surface">
      <div 
        className="flex items-center justify-between p-3 cursor-pointer hover:bg-surface-elevated transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3 flex-wrap">
          {expanded ? <ChevronDown className="h-4 w-4 text-muted" /> : <ChevronRight className="h-4 w-4 text-muted" />}
          {isPrivate ? <Server className="h-4 w-4 text-emerald-400" /> : <Globe className="h-4 w-4 text-amber-400" />}
          <span className="font-mono text-sm font-bold text-primary">{group.ip}</span>
          
          <span className={`text-[10px] font-semibold uppercase tracking-wider px-2 py-0.5 rounded border ${badgeColor}`}>
            {group.classification}
          </span>

          <span className="text-[10px] font-mono bg-surface-elevated border border-border-subtle px-1.5 py-0.5 rounded text-muted">
            Role: {group.role}
          </span>

          {group.findingCount > 0 && (
            <span className="text-[10px] font-semibold bg-red-500/10 text-red-400 border border-red-500/30 px-1.5 py-0.5 rounded flex items-center gap-1">
              <ShieldAlert className="h-3 w-3" />
              {group.findingCount} Finding{group.findingCount > 1 ? 's' : ''}
            </span>
          )}
        </div>

        <span className="text-xs bg-surface-elevated border border-border-subtle px-2 py-0.5 rounded text-muted font-mono">
          {group.totalFlows} flows
        </span>
      </div>

      {/* Expanded Entity Context Metadata */}
      {expanded && (
        <div className="border-t border-border-subtle bg-background p-3 space-y-2">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2 text-xs">
            {group.relatedDomains.length > 0 && (
              <div className="bg-surface p-2 rounded border border-border-subtle">
                <span className="text-muted text-[10px] uppercase font-semibold tracking-wider block">Domain(s)</span>
                <span className="font-mono text-secondary truncate block">{group.relatedDomains.join(', ')}</span>
              </div>
            )}

            {group.services.length > 0 && (
              <div className="bg-surface p-2 rounded border border-border-subtle">
                <span className="text-muted text-[10px] uppercase font-semibold tracking-wider block">Observed Services</span>
                <span className="font-mono text-secondary truncate block">{group.services.join(', ')}</span>
              </div>
            )}

            {group.firstSeen && (
              <div className="bg-surface p-2 rounded border border-border-subtle">
                <span className="text-muted text-[10px] uppercase font-semibold tracking-wider block">First / Last Seen</span>
                <span className="font-mono text-muted text-[11px] block">
                  {new Date(group.firstSeen).toLocaleTimeString()} — {new Date(group.lastSeen).toLocaleTimeString()}
                </span>
              </div>
            )}
          </div>

          <div className="pt-2 border-t border-border-subtle">
            {group.categories.map((cat: any) => (
              <CategoryGroup key={cat.name} category={cat} onRowClick={onRowClick} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function CategoryGroup({ category, onRowClick }: { category: any, onRowClick: (flow: FlowListItem) => void }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border-b border-border-subtle last:border-0">
      <div 
        className="flex items-center justify-between p-2 pl-4 cursor-pointer hover:bg-surface-elevated transition-colors bg-surface/50 rounded"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="h-3 w-3 text-muted" /> : <ChevronRight className="h-3 w-3 text-muted" />}
          <span className="text-xs font-medium text-secondary uppercase tracking-wider">{category.name}</span>
        </div>
        <span className="text-[10px] text-muted font-mono">{category.flows.length} flows</span>
      </div>

      {expanded && (
        <div className="overflow-x-auto border-t border-border-subtle my-1">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-surface-elevated border-b border-border-subtle">
                <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-muted">Timestamp</th>
                <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-muted">Source</th>
                <th className="px-1 py-2" />
                <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-muted">Destination</th>
                <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-muted">Proto</th>
                <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-muted hidden sm:table-cell">Service</th>
                <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-muted hidden md:table-cell">Bytes ↑/↓</th>
                <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-muted hidden lg:table-cell">Duration</th>
                <th className="px-3 py-2 text-left text-[10px] font-semibold uppercase tracking-wide text-muted">State</th>
              </tr>
            </thead>
            <tbody>
              {category.flows.map((flow: FlowListItem, idx: number) => (
                <FlowRow key={`${flow.flow_id}-${idx}`} flow={flow} onClick={onRowClick} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
