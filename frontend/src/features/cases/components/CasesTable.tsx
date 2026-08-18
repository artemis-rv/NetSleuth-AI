import { useNavigate } from 'react-router-dom';
import { ChevronRight } from 'lucide-react';
import type { CaseResponse, PaginatedCases } from '../types';
import { CaseStatusBadge, CasePriorityBadge } from './CaseBadge';
import { Button } from '../../../components/ui/Button';

interface CasesTableProps {
  data: PaginatedCases;
  currentPage: number;
  onPageChange: (page: number) => void;
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
  });
}

function CaseRow({ c }: { c: CaseResponse }) {
  const navigate = useNavigate();
  return (
    <tr
      className="border-b border-border-subtle hover:bg-surface-elevated/50 cursor-pointer transition-colors"
      onClick={() => navigate(`/investigations/${c.case_id}`)}
      role="link"
      tabIndex={0}
      aria-label={`Open case ${c.title}`}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') navigate(`/investigations/${c.case_id}`);
      }}
    >
      <td className="px-4 py-3 font-mono text-xs text-muted select-all">
        {c.case_id.split('-')[0]}…
      </td>
      <td className="px-4 py-3">
        <div className="text-sm font-medium text-primary leading-tight">{c.title}</div>
        {c.description && (
          <div className="text-xs text-muted mt-0.5 line-clamp-1">{c.description}</div>
        )}
      </td>
      <td className="px-4 py-3">
        <CaseStatusBadge status={c.status} />
      </td>
      <td className="px-4 py-3">
        <CasePriorityBadge priority={c.priority} />
      </td>
      <td className="px-4 py-3 text-xs text-secondary whitespace-nowrap">
        {formatDate(c.updated_at)}
      </td>
      <td className="px-4 py-3">
        <ChevronRight className="h-4 w-4 text-muted" />
      </td>
    </tr>
  );
}

export function CasesTable({ data, currentPage, onPageChange }: CasesTableProps) {
  const totalPages = Math.ceil(data.total / data.page_size);

  return (
    <div>
      <div className="overflow-x-auto rounded-lg border border-border-subtle">
        <table className="w-full text-sm" role="grid" aria-label="Investigations">
          <thead>
            <tr className="border-b border-border-subtle bg-surface">
              <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wider">
                ID
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wider">
                Title
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wider">
                Status
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wider">
                Priority
              </th>
              <th className="px-4 py-3 text-left text-xs font-medium text-muted uppercase tracking-wider">
                Updated
              </th>
              <th className="px-4 py-3 w-8" aria-label="Open" />
            </tr>
          </thead>
          <tbody className="bg-surface divide-y divide-border-subtle">
            {data.items.map((c) => (
              <CaseRow key={c.case_id} c={c} />
            ))}
          </tbody>
        </table>
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-between mt-4 text-sm">
          <span className="text-muted">
            Showing {(currentPage - 1) * data.page_size + 1}–
            {Math.min(currentPage * data.page_size, data.total)} of {data.total}
          </span>
          <div className="flex items-center gap-2">
            <Button
              variant="secondary"
              size="sm"
              disabled={currentPage <= 1}
              onClick={() => onPageChange(currentPage - 1)}
              aria-label="Previous page"
            >
              Previous
            </Button>
            <span className="text-secondary px-2">
              Page {currentPage} of {totalPages}
            </span>
            <Button
              variant="secondary"
              size="sm"
              disabled={currentPage >= totalPages}
              onClick={() => onPageChange(currentPage + 1)}
              aria-label="Next page"
            >
              Next
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// Skeleton loader for the table
export function CasesTableSkeleton() {
  return (
    <div className="overflow-x-auto rounded-lg border border-border-subtle animate-pulse">
      <table className="w-full">
        <thead>
          <tr className="border-b border-border-subtle bg-surface">
            {['ID', 'Title', 'Status', 'Priority', 'Updated', ''].map((_h, i) => (
              <th key={i} className="px-4 py-3">
                <div className="h-3 rounded bg-surface-elevated w-16" />
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {Array.from({ length: 5 }).map((_, i) => (
            <tr key={i} className="border-b border-border-subtle">
              <td className="px-4 py-3"><div className="h-3 rounded bg-surface-elevated w-12" /></td>
              <td className="px-4 py-3"><div className="h-3 rounded bg-surface-elevated w-40" /></td>
              <td className="px-4 py-3"><div className="h-5 rounded bg-surface-elevated w-20" /></td>
              <td className="px-4 py-3"><div className="h-5 rounded bg-surface-elevated w-16" /></td>
              <td className="px-4 py-3"><div className="h-3 rounded bg-surface-elevated w-24" /></td>
              <td className="px-4 py-3" />
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
