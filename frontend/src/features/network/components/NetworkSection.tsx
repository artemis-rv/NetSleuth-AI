import { useState, useMemo } from 'react';
import { AlertCircle, ChevronDown, ChevronRight, Activity, ChevronLeft } from 'lucide-react';
import { useFlowsQuery } from '../hooks';
import { FlowRow } from './FlowRow';
import { FlowFilters } from './FlowFilters';
import { FlowDetailDrawer } from './FlowDetailDrawer';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { FlowListItem, FlowsFilters } from '../types';

interface NetworkSectionProps {
  caseId: string;
}

export function NetworkSection({ caseId }: NetworkSectionProps) {
  const [filters, setFilters] = useState<FlowsFilters>({ page: 1, page_size: 50 });
  const [selectedFlowId, setSelectedFlowId] = useState<string | null>(null);

  const { data, isLoading, isError, error } = useFlowsQuery(caseId, filters);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 50)) : 0;
  const currentPage = filters.page ?? 1;

  function handleRowClick(flow: FlowListItem) {
    setSelectedFlowId(flow.flow_id);
  }

  // Group flows by distinct IP
  const groupedData = useMemo(() => {
    if (!data?.items) return [];

    const ipMap = new Map<string, FlowListItem[]>();

    // Gather all flows per IP (both source and destination)
    data.items.forEach(flow => {
      if (!ipMap.has(flow.src_ip)) ipMap.set(flow.src_ip, []);
      ipMap.get(flow.src_ip)!.push(flow);

      if (flow.dst_ip !== flow.src_ip) {
        if (!ipMap.has(flow.dst_ip)) ipMap.set(flow.dst_ip, []);
        ipMap.get(flow.dst_ip)!.push(flow);
      }
    });

    // Transform into array and sort by flow count
    return Array.from(ipMap.entries())
      .map(([ip, flows]) => {
        // Build categories
        const incoming = flows.filter(f => f.dst_ip === ip);
        const outgoing = flows.filter(f => f.src_ip === ip);
        
        // Find distinct protocols
        const protocols = Array.from(new Set(flows.map(f => f.protocol || f.service).filter(Boolean)));
        const protocolGroups = protocols.map(proto => ({
          name: proto?.toUpperCase() || 'UNKNOWN',
          flows: flows.filter(f => (f.protocol || f.service) === proto)
        }));

        return {
          ip,
          totalFlows: flows.length,
          categories: [
            { name: 'Incoming', flows: incoming },
            { name: 'Outgoing', flows: outgoing },
            ...protocolGroups
          ].filter(c => c.flows.length > 0)
        };
      })
      .sort((a, b) => b.totalFlows - a.totalFlows);

  }, [data]);

  return (
    <div className="space-y-4">
      <FlowFilters filters={filters} onChange={setFilters} />

      {data && (
        <p className="text-xs text-muted">
          {data.total.toLocaleString()} flow{data.total !== 1 ? 's' : ''} captured
        </p>
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
        <div className="space-y-2">
          {groupedData.map(group => (
            <IPGroup key={group.ip} group={group} onRowClick={handleRowClick} />
          ))}
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
          caseId={caseId}
          flowId={selectedFlowId}
          onClose={() => setSelectedFlowId(null)}
        />
      )}
    </div>
  );
}

function IPGroup({ group, onRowClick }: { group: any, onRowClick: (flow: FlowListItem) => void }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <div className="border border-border-subtle rounded overflow-hidden bg-surface">
      <div 
        className="flex items-center justify-between p-3 cursor-pointer hover:bg-surface-elevated transition-colors"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-3">
          {expanded ? <ChevronDown className="h-4 w-4 text-muted" /> : <ChevronRight className="h-4 w-4 text-muted" />}
          <Activity className="h-4 w-4 text-accent" />
          <span className="font-mono text-sm font-semibold text-primary">{group.ip}</span>
        </div>
        <span className="text-xs bg-surface-elevated border border-border-subtle px-2 py-0.5 rounded text-muted">
          {group.totalFlows} flows
        </span>
      </div>
      
      {expanded && (
        <div className="border-t border-border-subtle bg-background">
          {group.categories.map((cat: any) => (
            <CategoryGroup key={cat.name} category={cat} onRowClick={onRowClick} />
          ))}
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
        className="flex items-center justify-between p-2 pl-8 cursor-pointer hover:bg-surface-elevated transition-colors bg-surface/50"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex items-center gap-2">
          {expanded ? <ChevronDown className="h-3 w-3 text-muted" /> : <ChevronRight className="h-3 w-3 text-muted" />}
          <span className="text-xs font-medium text-secondary uppercase tracking-wider">{category.name}</span>
        </div>
        <span className="text-[10px] text-muted">{category.flows.length}</span>
      </div>

      {expanded && (
        <div className="overflow-x-auto border-t border-border-subtle">
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
