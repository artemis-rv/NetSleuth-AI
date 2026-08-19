import { useState } from 'react';
import { Search, SlidersHorizontal, X } from 'lucide-react';
import type { FindingsFilters } from '../types';

interface FindingFiltersProps {
  filters: FindingsFilters;
  onChange: (filters: FindingsFilters) => void;
}

const DECISION_OPTIONS = [
  { value: '', label: 'All States' },
  { value: 'pending', label: 'Pending' },
  { value: 'under_review', label: 'Under Review' },
  { value: 'confirmed_tp', label: 'Confirmed TP' },
  { value: 'confirmed_fp', label: 'Confirmed FP' },
];

export function FindingFilters({ filters, onChange }: FindingFiltersProps) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const hasActive = !!(filters.activity || filters.decision_state || filters.min_risk !== undefined);

  const advancedCount = (filters.min_risk !== undefined ? 1 : 0);

  function handleReset() {
    onChange({ page: 1, page_size: filters.page_size });
  }

  return (
    <div className="space-y-2">
      {/* Primary filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        {/* Activity search */}
        <div className="relative flex-1 min-w-[200px] max-w-sm">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted pointer-events-none" aria-hidden="true" />
          <input
            id="finding-activity-filter"
            type="text"
            value={filters.activity ?? ''}
            onChange={(e) => onChange({ ...filters, activity: e.target.value || undefined, page: 1 })}
            placeholder="Filter by activity…"
            className="w-full pl-8 pr-3 h-8 text-[13px] bg-surface-elevated/50 border border-border-subtle rounded text-primary placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent focus:border-accent transition-all"
          />
        </div>

        {/* Decision state */}
        <select
          id="finding-decision-filter"
          value={filters.decision_state ?? ''}
          onChange={(e) => onChange({ ...filters, decision_state: e.target.value || undefined, page: 1 })}
          className="h-8 pl-3 pr-8 text-[13px] bg-surface-elevated/50 border border-border-subtle rounded text-primary focus:outline-none focus:ring-1 focus:ring-accent focus:border-accent transition-all"
          aria-label="Filter by decision state"
        >
          {DECISION_OPTIONS.map((o) => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </select>

        {/* Advanced toggle */}
        <button
          id="finding-advanced-toggle"
          onClick={() => setShowAdvanced((p) => !p)}
          className={`flex items-center gap-1.5 px-3 h-8 text-[13px] transition-colors rounded border ${
            showAdvanced || advancedCount > 0
              ? 'bg-surface-elevated text-primary border-border-subtle'
              : 'bg-transparent text-secondary hover:text-primary border-border-subtle hover:bg-surface-elevated/50'
          }`}
        >
          <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
          {advancedCount > 0 ? `Advanced · ${advancedCount}` : 'Advanced'}
        </button>

        {/* Reset */}
        {hasActive && (
          <button
            id="finding-reset-filter"
            onClick={handleReset}
            className="flex items-center gap-1.5 px-3 h-8 text-[13px] text-muted hover:text-primary hover:bg-surface/50 rounded transition-colors"
            aria-label="Clear all filters"
          >
            <X className="h-3.5 w-3.5" />
            Clear filters
          </button>
        )}
      </div>

      {/* Advanced options */}
      {showAdvanced && (
        <div className="flex items-center gap-3 px-3 py-2 bg-surface-elevated/30 border border-border-subtle rounded mt-2">
          <label htmlFor="finding-min-risk" className="text-[12px] uppercase tracking-wider text-muted font-semibold whitespace-nowrap">
            Min Risk Score
          </label>
          <input
            id="finding-min-risk"
            type="number"
            min={0}
            max={1}
            step={0.05}
            value={filters.min_risk ?? ''}
            onChange={(e) => {
              const v = parseFloat(e.target.value);
              onChange({ ...filters, min_risk: isNaN(v) ? undefined : v, page: 1 });
            }}
            placeholder="0.00 – 1.00"
            className="w-28 h-7 px-2 text-[13px] bg-surface border border-border-subtle rounded text-primary placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent focus:border-accent"
          />
        </div>
      )}
    </div>
  );
}
