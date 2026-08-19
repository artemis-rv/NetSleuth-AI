import { useState } from 'react';
import { useCasesQuery } from '../hooks';
import { CasesTable, CasesTableSkeleton } from '../components/CasesTable';
import { EmptyState } from '../../../components/feedback/EmptyState';
import { ErrorState } from '../../../components/feedback/ErrorState';
import { Button } from '../../../components/ui/Button';
import { useNavigate, Link } from 'react-router-dom';
import { Plus, Filter } from 'lucide-react';
import { useAuth } from '../../../auth/auth-context';
import { CASE_STATUSES, CASE_PRIORITIES, CASE_STATUS_LABELS, CASE_PRIORITY_LABELS } from '../types';
import type { CasesFilters } from '../types';

export function InvestigationsPage() {
  const navigate = useNavigate();
  const { user } = useAuth();

  const [page, setPage] = useState(1);
  const [status, setStatus] = useState('');
  const [priority, setPriority] = useState('');
  const [sortBy, setSortBy] = useState<CasesFilters['sort_by']>('updated_at');

  const filters: CasesFilters = {
    page,
    page_size: 25,
    sort_by: sortBy,
    ...(status ? { status } : {}),
    ...(priority ? { priority } : {}),
  };

  const { data, isLoading, isError, error, refetch } = useCasesQuery(filters);

  const canCreate = user?.role === 'investigator' || user?.role === 'administrator';

  const handleFilterChange = () => {
    setPage(1); // reset to first page on filter change
  };

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary">Investigations</h1>
          {data && (
            <p className="text-sm text-muted mt-1">{data.total} total</p>
          )}
        </div>
        {canCreate && (
          <Button onClick={() => navigate('/investigations/new')}>
            <Plus className="h-4 w-4 mr-2" aria-hidden="true" />
            New Investigation
          </Button>
        )}
      </div>

      {/* Filters */}
      <div
        className="flex flex-wrap items-center gap-3 mb-6 p-3 rounded-lg bg-surface border border-border-subtle"
        aria-label="Filter investigations"
      >
        <Filter className="h-4 w-4 text-muted flex-shrink-0" aria-hidden="true" />

        <div className="flex items-center gap-2">
          <label htmlFor="filter-status" className="text-xs text-muted">Status</label>
          <select
            id="filter-status"
            value={status}
            onChange={(e) => { setStatus(e.target.value); handleFilterChange(); }}
            className="h-8 rounded border border-border-subtle bg-surface-elevated px-2 py-0 text-xs text-primary focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent transition-all duration-200"
          >
            <option value="">All</option>
            {CASE_STATUSES.map((s) => (
              <option key={s} value={s}>{CASE_STATUS_LABELS[s] ?? s.replace(/_/g, ' ')}</option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2">
          <label htmlFor="filter-priority" className="text-xs text-muted">Priority</label>
          <select
            id="filter-priority"
            value={priority}
            onChange={(e) => { setPriority(e.target.value); handleFilterChange(); }}
            className="h-8 rounded border border-border-subtle bg-surface-elevated px-2 py-0 text-xs text-primary focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent transition-all duration-200"
          >
            <option value="">All</option>
            {CASE_PRIORITIES.map((p) => (
              <option key={p} value={p}>{CASE_PRIORITY_LABELS[p] ?? p}</option>
            ))}
          </select>
        </div>

        <div className="flex items-center gap-2">
          <label htmlFor="filter-sort" className="text-xs text-muted">Sort by</label>
          <select
            id="filter-sort"
            value={sortBy}
            onChange={(e) => { setSortBy(e.target.value as CasesFilters['sort_by']); handleFilterChange(); }}
            className="h-8 rounded border border-border-subtle bg-surface-elevated px-2 py-0 text-xs text-primary focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-accent transition-all duration-200"
          >
            <option value="updated_at">Last Updated</option>
            <option value="created_at">Created</option>
            <option value="priority">Priority</option>
            <option value="status">Status</option>
          </select>
        </div>

        {(status || priority) && (
          <button
            type="button"
            onClick={() => { setStatus(''); setPriority(''); setPage(1); }}
            className="text-xs text-accent hover:text-accent/80 transition-colors ml-auto"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table area */}
      {isLoading && <CasesTableSkeleton />}

      {isError && (
        <ErrorState
          error={error as Error}
          retry={() => refetch()}
        />
      )}

      {!isLoading && !isError && data && data.items.length === 0 && (
        <EmptyState
          title="No investigations found"
          description={
            status || priority
              ? 'No investigations match the current filters.'
              : 'No investigations have been created yet.'
          }
          action={
            canCreate ? (
              <Link to="/investigations/new">
                <Button>
                  <Plus className="h-4 w-4 mr-2" aria-hidden="true" />
                  Create Investigation
                </Button>
              </Link>
            ) : undefined
          }
        />
      )}

      {!isLoading && !isError && data && data.items.length > 0 && (
        <CasesTable
          data={data}
          currentPage={page}
          onPageChange={setPage}
        />
      )}
    </div>
  );
}
