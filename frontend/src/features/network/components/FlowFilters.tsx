import { X } from 'lucide-react';
import type { FlowsFilters } from '../types';

interface FlowFiltersProps {
  filters: FlowsFilters;
  onChange: (filters: FlowsFilters) => void;
}

const PROTOCOL_OPTIONS = [
  { value: '', label: 'All Protocols' },
  { value: 'tcp', label: 'TCP' },
  { value: 'udp', label: 'UDP' },
  { value: 'icmp', label: 'ICMP' },
];

export function FlowFilters({ filters, onChange }: FlowFiltersProps) {
  const hasActive = !!(filters.src_ip || filters.dst_ip || filters.protocol || filters.service);

  function handleReset() {
    onChange({ page: 1, page_size: filters.page_size });
  }

  return (
    <div className="flex items-center gap-2 flex-wrap">
      <input
        id="flow-src-ip-filter"
        type="text"
        value={filters.src_ip ?? ''}
        onChange={(e) => onChange({ ...filters, src_ip: e.target.value || undefined, page: 1 })}
        placeholder="Source IP"
        className="w-36 px-2.5 py-1.5 text-xs bg-surface-elevated border border-border-subtle rounded text-primary font-mono placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent"
      />

      <input
        id="flow-dst-ip-filter"
        type="text"
        value={filters.dst_ip ?? ''}
        onChange={(e) => onChange({ ...filters, dst_ip: e.target.value || undefined, page: 1 })}
        placeholder="Dest IP"
        className="w-36 px-2.5 py-1.5 text-xs bg-surface-elevated border border-border-subtle rounded text-primary font-mono placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent"
      />

      <select
        id="flow-protocol-filter"
        value={filters.protocol ?? ''}
        onChange={(e) => onChange({ ...filters, protocol: e.target.value || undefined, page: 1 })}
        className="px-2.5 py-1.5 text-xs bg-surface-elevated border border-border-subtle rounded text-primary focus:outline-none focus:ring-1 focus:ring-accent"
        aria-label="Filter by protocol"
      >
        {PROTOCOL_OPTIONS.map((o) => (
          <option key={o.value} value={o.value}>{o.label}</option>
        ))}
      </select>

      <input
        id="flow-service-filter"
        type="text"
        value={filters.service ?? ''}
        onChange={(e) => onChange({ ...filters, service: e.target.value || undefined, page: 1 })}
        placeholder="Service"
        className="w-28 px-2.5 py-1.5 text-xs bg-surface-elevated border border-border-subtle rounded text-primary font-mono placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent"
      />

      {hasActive && (
        <button
          id="flow-reset-filter"
          onClick={handleReset}
          className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-muted hover:text-primary transition-colors"
          aria-label="Reset all flow filters"
        >
          <X className="h-3.5 w-3.5" />
          Reset
        </button>
      )}
    </div>
  );
}
