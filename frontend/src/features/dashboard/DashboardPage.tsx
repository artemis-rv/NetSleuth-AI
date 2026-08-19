import { useNavigate, Link } from 'react-router-dom';
import { Plus, ArrowRight } from 'lucide-react';
import { useCasesQuery } from '../cases/hooks';
import { CaseStatusBadge, CasePriorityBadge } from '../cases/components/CaseBadge';
import { StatCard } from './StatCard';
import { Button } from '../../components/ui/Button';
import { EmptyState } from '../../components/feedback/EmptyState';
import { ErrorState } from '../../components/feedback/ErrorState';
import { useAuth } from '../../auth/auth-context';

// Derive stats from bounded query (not fetching all records)
const STATS_PAGE_SIZE = 25;

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', { month: 'short', day: '2-digit', year: 'numeric' });
}

export function DashboardPage() {
  const { user } = useAuth();
  const navigate = useNavigate();

  // Fetch the most recently updated cases for the dashboard
  const { data, isLoading, isError, error, refetch } = useCasesQuery({
    page: 1,
    page_size: STATS_PAGE_SIZE,
    sort_by: 'updated_at',
  });

  const canCreate = user?.role === 'investigator' || user?.role === 'administrator';

  // Derive stats from bounded data set
  const openCount = data?.items.filter((c) => c.status?.toUpperCase() === 'OPEN').length ?? 0;
  const activeCount = data?.items.filter((c) => c.status?.toUpperCase() === 'ACTIVE').length ?? 0;
  const highPriorityCount = data?.items.filter(
    (c) => c.priority?.toUpperCase() === 'HIGH' || c.priority?.toUpperCase() === 'CRITICAL'
  ).length ?? 0;
  const recentCases = data?.items.slice(0, 10) ?? [];

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-8">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-primary">Dashboard</h1>
          <p className="text-sm text-muted mt-1">Welcome back, {user?.username}</p>
        </div>
        {canCreate && (
          <Button onClick={() => navigate('/investigations/new')}>
            <Plus className="h-4 w-4 mr-2" aria-hidden="true" />
            New Investigation
          </Button>
        )}
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
        <StatCard
          title="Total Investigations"
          value={data?.total ?? '—'}
          description="All accessible cases"
          loading={isLoading}
        />
        <StatCard
          title="Open"
          value={isLoading ? '—' : openCount}
          description={`of ${data?.items.length ?? 0} shown`}
          variant="info"
          loading={isLoading}
        />
        <StatCard
          title="Active"
          value={isLoading ? '—' : activeCount}
          description="Currently in progress"
          loading={isLoading}
        />
        <StatCard
          title="High Priority"
          value={isLoading ? '—' : highPriorityCount}
          description="Critical or High"
          variant={highPriorityCount > 0 ? 'warning' : 'default'}
          loading={isLoading}
        />
      </div>

      {/* Recent Investigations */}
      <div className="mb-4 flex items-center justify-between">
        <h2 className="text-base font-semibold text-primary">Recent Investigations</h2>
        <Link
          to="/investigations"
          className="inline-flex items-center text-sm text-accent hover:text-accent/80 transition-colors"
        >
          View all
          <ArrowRight className="h-3.5 w-3.5 ml-1" aria-hidden="true" />
        </Link>
      </div>

      {isError && <ErrorState error={error as Error} retry={() => refetch()} />}

      {!isLoading && !isError && recentCases.length === 0 && (
        <EmptyState
          title="No investigations yet"
          description="Create your first investigation to get started."
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
          className="h-48"
        />
      )}

      {!isError && recentCases.length > 0 && (
        <div className="rounded-lg border border-border-subtle overflow-hidden">
          <table className="w-full text-sm" aria-label="Recent investigations">
            <thead>
              <tr className="border-b border-border-subtle bg-surface">
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wider">Title</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wider">Status</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wider">Priority</th>
                <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wider">Updated</th>
                <th className="px-4 py-3 w-8" aria-label="Open" />
              </tr>
            </thead>
            <tbody className="bg-surface divide-y divide-border-subtle">
              {recentCases.map((c) => (
                <tr
                  key={c.case_id}
                  className="hover:bg-surface-elevated/50 cursor-pointer transition-colors"
                  onClick={() => navigate(`/investigations/${c.case_id}`)}
                  role="link"
                  tabIndex={0}
                  aria-label={`Open case ${c.title}`}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') navigate(`/investigations/${c.case_id}`);
                  }}
                >
                  <td className="px-4 py-3">
                    <div className="text-sm font-medium text-primary leading-tight line-clamp-1">{c.title}</div>
                  </td>
                  <td className="px-4 py-3"><CaseStatusBadge status={c.status} /></td>
                  <td className="px-4 py-3"><CasePriorityBadge priority={c.priority} /></td>
                  <td className="px-4 py-3 text-xs text-secondary whitespace-nowrap">{formatDate(c.updated_at)}</td>
                  <td className="px-4 py-3">
                    <ArrowRight className="h-3.5 w-3.5 text-muted" aria-hidden="true" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
