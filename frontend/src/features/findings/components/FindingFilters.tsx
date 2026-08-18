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

  function handleReset() {
    onChange({ page: 1, page_size: filters.page_size });
  }

  return (
    <div className="space-y-2">
      {/* Primary filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        {/* Activity search */}
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted pointer-events-none" aria-hidden="true" />
          <input
            id="finding-activity-filter"
            type="text"
            value={filters.activity ?? ''}
            onChange={(e) => onChange({ ...filters, activity: e.target.value || undefined, page: 1 })}
            placeholder="Filter by activity…"
            className="w-full pl-8 pr-3 py-1.5 text-sm bg-surface-elevated border border-border-subtle rounded text-primary placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>

        {/* Decision state */}
        <select
          id="finding-decision-filter"
          value={filters.decision_state ?? ''}
          onChange={(e) => onChange({ ...filters, decision_state: e.target.value || undefined, page: 1 })}
          className="py-1.5 pl-3 pr-8 text-sm bg-surface-elevated border border-border-subtle rounded text-primary focus:outline-none focus:ring-1 focus:ring-accent"
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
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-secondary hover:text-primary border border-border-subtle rounded hover:bg-surface-elevated transition-colors"
        >
          <SlidersHorizontal className="h-3.5 w-3.5" aria-hidden="true" />
          Advanced
        </button>

        {/* Reset */}
        {hasActive && (
          <button
            id="finding-reset-filter"
            onClick={handleReset}
            className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-muted hover:text-primary transition-colors"
            aria-label="Reset all filters"
          >
            <X className="h-3.5 w-3.5" />
            Reset
          </button>
        )}
      </div>

      {/* Advanced options */}
      {showAdvanced && (
        <div className="flex items-center gap-3 px-3 py-2.5 bg-surface-elevated/50 border border-border-subtle rounded">
          <label htmlFor="finding-min-risk" className="text-xs text-muted whitespace-nowrap">
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
            className="w-32 px-2 py-1 text-sm bg-surface border border-border-subtle rounded text-primary placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent"
          />
        </div>
      )}
    </div>
  );
}
