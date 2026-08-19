import { useState } from 'react';
import { AlertCircle, ChevronLeft, ChevronRight, Eye, Info } from 'lucide-react';
import { useCaseReportsQuery } from '../hooks';
import { ReportDetailModal } from './ReportDetailModal';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { ReportResponse, ReportFilters } from '../types';

interface ReportsSectionProps {
  caseId: string;
}

export function ReportsSection({ caseId }: ReportsSectionProps) {
  const [filters, setFilters] = useState<ReportFilters>({ page: 1, page_size: 25 });
  const [selectedReport, setSelectedReport] = useState<ReportResponse | null>(null);

  const { data, isLoading, isError, error } = useCaseReportsQuery(caseId, filters);

  const totalPages = data ? Math.ceil(data.total / (filters.page_size ?? 25)) : 0;
  const currentPage = filters.page ?? 1;

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-semibold text-primary">Forensic Investigation Reports</h3>
          <p className="text-xs text-muted">Official generated case reports and chain of custody attestations</p>
        </div>
        {data && (
          <span className="text-xs text-muted">
            {data.total.toLocaleString()} report{data.total !== 1 ? 's' : ''}
          </span>
        )}
      </div>

      <div className="flex items-start gap-2 p-3 rounded bg-surface-elevated/50 border border-border-subtle text-xs text-muted">
        <Info className="h-4 w-4 text-accent flex-shrink-0 mt-0.5" />
        <span>
          Investigation reports are automatically synthesized and signed by the backend report engine upon investigation completion.
        </span>
      </div>

      {isLoading && (
        <div className="flex items-center justify-center py-12">
          <Spinner size={28} />
        </div>
      )}

      {isError && (
        <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
          <AlertCircle className="h-4 w-4 flex-shrink-0" />
          Failed to load reports. {(error as Error)?.message}
        </div>
      )}

      {data && data.items.length === 0 && (
        <EmptyState
          title="No Reports Generated"
          description="Reports will appear here once synthesized by the automated report engine."
        />
      )}

      {data && data.items.length > 0 && (
        <>
          <div className="border border-border-subtle rounded overflow-hidden overflow-x-auto">
            <table className="w-full text-sm" role="grid" aria-label="Reports table">
              <thead>
                <tr className="bg-surface-elevated border-b border-border-subtle">
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Report Title / ID</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Type</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Format</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Version</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Generated</th>
                  <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">SHA-256</th>
                  <th className="px-4 py-2.5 text-right text-xs font-semibold uppercase tracking-wide text-muted">Action</th>
                </tr>
              </thead>
              <tbody>
                {data.items.map((rep) => (
                  <tr key={rep.report_id} className="border-b border-border-subtle hover:bg-surface-elevated/40 transition-colors">
                    <td className="px-4 py-2.5 text-xs font-medium text-primary">
                      {rep.title || `Report ${rep.report_id.slice(0, 8)}`}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-secondary font-mono uppercase">{rep.report_type}</td>
                    <td className="px-4 py-2.5 text-xs text-muted font-mono uppercase">{rep.format}</td>
                    <td className="px-4 py-2.5 text-xs text-secondary font-mono">v{rep.version}</td>
                    <td className="px-4 py-2.5 text-xs text-muted tabular-nums">{new Date(rep.generated_at).toLocaleString()}</td>
                    <td className="px-4 py-2.5 text-xs text-muted font-mono truncate max-w-[140px]" title={rep.sha256}>
                      {rep.sha256}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        onClick={() => setSelectedReport(rep)}
                        className="flex items-center gap-1 px-2.5 py-1 text-xs text-accent hover:bg-accent/10 border border-accent/30 rounded transition-colors ml-auto"
                      >
                        <Eye className="h-3.5 w-3.5" />
                        Details
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-xs text-muted">Page {currentPage} of {totalPages}</p>
              <div className="flex items-center gap-1">
                <button
                  onClick={() => setFilters((f) => ({ ...f, page: Math.max(1, currentPage - 1) }))}
                  disabled={currentPage <= 1}
                  className="p-1 rounded border border-border-subtle disabled:opacity-40"
                >
                  <ChevronLeft className="h-4 w-4" />
                </button>
                <button
                  onClick={() => setFilters((f) => ({ ...f, page: Math.min(totalPages, currentPage + 1) }))}
                  disabled={currentPage >= totalPages}
                  className="p-1 rounded border border-border-subtle disabled:opacity-40"
                >
                  <ChevronRight className="h-4 w-4" />
                </button>
              </div>
            </div>
          )}
        </>
      )}

      <ReportDetailModal report={selectedReport} onClose={() => setSelectedReport(null)} />
    </div>
  );
}
