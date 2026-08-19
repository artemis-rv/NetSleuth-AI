import React from 'react';
import { Search, Filter, ArrowUpDown } from 'lucide-react';
import type { FlowsFilters } from '../types';

interface EndpointFiltersProps {
  filters: FlowsFilters;
  onChange: (filters: FlowsFilters) => void;
}

export function EndpointFilters({ filters, onChange }: EndpointFiltersProps) {
  function handleSearchChange(e: React.ChangeEvent<HTMLInputElement>) {
    onChange({ ...filters, search_ip: e.target.value || undefined, page: 1 });
  }

  function handleScopeChange(e: React.ChangeEvent<HTMLSelectElement>) {
    onChange({ ...filters, network_scope: e.target.value || undefined, page: 1 });
  }

  function handleProtocolChange(e: React.ChangeEvent<HTMLInputElement>) {
    onChange({ ...filters, protocol: e.target.value || undefined, page: 1 });
  }

  function handleSeverityChange(e: React.ChangeEvent<HTMLSelectElement>) {
    onChange({ ...filters, severity: e.target.value || undefined, page: 1 });
  }

  function handleSortChange(e: React.ChangeEvent<HTMLSelectElement>) {
    onChange({ ...filters, sort_by: e.target.value || 'risk_score', page: 1 });
  }

  return (
    <div className="bg-surface border border-border-subtle rounded-lg p-3 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {/* IP Search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted" />
          <input
            type="text"
            placeholder="Filter by IP address or domain..."
            value={filters.search_ip || ''}
            onChange={handleSearchChange}
            className="w-full bg-background border border-border-subtle rounded pl-9 pr-3 py-1.5 text-xs text-primary placeholder:text-muted focus:outline-none focus:border-accent"
          />
        </div>

        {/* Scope Filter */}
        <div className="flex items-center gap-2">
          <Filter className="h-3.5 w-3.5 text-muted" />
          <select
            value={filters.network_scope || ''}
            onChange={handleScopeChange}
            className="bg-background border border-border-subtle rounded px-2.5 py-1.5 text-xs text-secondary focus:outline-none"
          >
            <option value="">All Network Scopes</option>
            <option value="PRIVATE/INTERNAL">Internal / Private</option>
            <option value="PUBLIC/EXTERNAL">External / Public</option>
          </select>

          {/* Severity Filter */}
          <select
            value={filters.severity || ''}
            onChange={handleSeverityChange}
            className="bg-background border border-border-subtle rounded px-2.5 py-1.5 text-xs text-secondary focus:outline-none"
          >
            <option value="">All Finding Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          {/* Protocol Filter */}
          <input
            type="text"
            placeholder="Proto (e.g. TCP, DNS)"
            value={filters.protocol || ''}
            onChange={handleProtocolChange}
            className="w-40 bg-background border border-border-subtle rounded px-2 py-1.5 text-xs text-primary focus:outline-none"
          />

          {/* Sort Selector */}
          <div className="flex items-center gap-1.5 border-l border-border-subtle pl-2">
            <ArrowUpDown className="h-3.5 w-3.5 text-muted" />
            <select
              value={filters.sort_by || 'risk_score'}
              onChange={handleSortChange}
              className="bg-background border border-border-subtle rounded px-2 py-1.5 text-xs text-secondary focus:outline-none font-mono"
            >
              <option value="risk_score">Sort by Risk Score</option>
              <option value="findings">Sort by Findings Count</option>
              <option value="anomaly_score">Sort by Anomaly Score</option>
              <option value="bytes">Sort by Total Bytes</option>
              <option value="flow_count">Sort by Flow Count</option>
              <option value="first_seen">Sort by First Seen</option>
              <option value="last_seen">Sort by Last Seen</option>
            </select>
          </div>
        </div>
      </div>
    </div>
  );
}
