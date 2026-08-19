import { useState } from 'react';
import { ShieldCheck, Lock, AlertCircle, ChevronLeft, ChevronRight, Download } from 'lucide-react';
import { useCaseEvidenceQuery, useCustodyItemsQuery } from '../hooks';
import { exportEvidenceBlob } from '../api';
import { IntegrityVerificationModal } from './IntegrityVerificationModal';
import { CustodyTimelineDrawer } from './CustodyTimelineDrawer';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import type { EvidenceResponse, EvidenceItemResponse, EvidenceFilters } from '../types';

function formatBytes(bytes: number | null): string {
  if (bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

interface EvidenceSectionProps {
  caseId: string;
}

export function EvidenceSection({ caseId }: EvidenceSectionProps) {
  const [filters, setFilters] = useState<EvidenceFilters>({ page: 1, page_size: 25 });
  const [selectedVerifyEvidence, setSelectedVerifyEvidence] = useState<EvidenceResponse | null>(null);
  const [selectedCustodyItem, setSelectedCustodyItem] = useState<EvidenceItemResponse | null>(null);
  const [exportNotice, setExportNotice] = useState<string | null>(null);
  const [exportingId, setExportingId] = useState<string | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  const { data: evidenceData, isLoading: evidenceLoading, isError: evidenceError, error: evErr } = useCaseEvidenceQuery(caseId, filters);
  const { data: custodyData } = useCustodyItemsQuery(caseId, filters);

  const totalPages = evidenceData ? Math.ceil(evidenceData.total / (filters.page_size ?? 25)) : 0;
  const currentPage = filters.page ?? 1;

  const handleExport = async (ev: EvidenceResponse) => {
    try {
      setExportError(null);
      setExportNotice(null);
      setExportingId(ev.evidence_id);
      await exportEvidenceBlob(ev.evidence_id, ev.file_name);
      setExportNotice(`Export initiated for ${ev.file_name}. Check your browser downloads.`);
      setTimeout(() => setExportNotice(null), 8000);
    } catch (err: any) {
      console.error('Export error:', err);
      setExportError(err.message || 'Failed to export evidence.');
    } finally {
      setExportingId(null);
    }
  };

  return (
    <div className="space-y-6">
      {/* Evidence Items Section */}
      <div className="space-y-3">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-sm font-semibold text-primary">Evidence Vault</h3>
            <p className="text-xs text-muted">Forensic artifacts and raw capture payloads registered to this investigation</p>
          </div>
          {evidenceData && (
            <span className="text-xs text-muted">
              {evidenceData.total.toLocaleString()} item{evidenceData.total !== 1 ? 's' : ''}
            </span>
          )}
        </div>

        {exportNotice && (
          <div className="p-3 rounded border border-blue-500/30 bg-blue-500/10 text-blue-300 text-xs">
            {exportNotice}
          </div>
        )}

        {exportError && (
          <div className="p-3 rounded border border-red-500/30 bg-red-500/10 text-red-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertCircle className="h-4 w-4 text-red-400 flex-shrink-0" />
              <span>{exportError}</span>
            </div>
            <button onClick={() => setExportError(null)} className="text-red-400 hover:text-red-200 font-semibold text-xs ml-2 flex-shrink-0">Dismiss</button>
          </div>
        )}

        {evidenceLoading && (
          <div className="flex items-center justify-center py-12">
            <Spinner size={28} />
          </div>
        )}

        {evidenceError && (
          <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
            <AlertCircle className="h-4 w-4 flex-shrink-0" />
            Failed to load evidence items. {(evErr as Error)?.message}
          </div>
        )}

        {evidenceData && evidenceData.items.length === 0 && (
          <EmptyState title="No Evidence Items" description="No evidence artifacts registered to this case yet." />
        )}

        {evidenceData && evidenceData.items.length > 0 && (
          <>
            <div className="border border-border-subtle rounded overflow-hidden overflow-x-auto">
              <table className="w-full text-sm" role="grid" aria-label="Evidence table">
                <thead>
                  <tr className="bg-surface-elevated border-b border-border-subtle">
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">File Name</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Format</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Size</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">SHA-256</th>
                    <th className="px-4 py-2.5 text-left text-xs font-semibold uppercase tracking-wide text-muted">Status</th>
                    <th className="px-4 py-2.5 text-right text-xs font-semibold uppercase tracking-wide text-muted">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {evidenceData.items.map((item) => (
                    <tr key={item.evidence_id} className="border-b border-border-subtle hover:bg-surface-elevated/40 transition-colors">
                      <td className="px-4 py-2.5 font-mono text-xs font-medium text-primary">{item.file_name}</td>
                      <td className="px-4 py-2.5 uppercase text-xs text-muted font-mono">{item.format}</td>
                      <td className="px-4 py-2.5 text-xs text-secondary font-mono">{formatBytes(item.size_bytes)}</td>
                      <td className="px-4 py-2.5 text-xs text-muted font-mono truncate max-w-[140px]" title={item.sha256}>{item.sha256}</td>
                      <td className="px-4 py-2.5 text-xs text-secondary">
                        <span className="inline-flex items-center rounded border border-border-subtle bg-surface-elevated px-2 py-0.5 text-[10px] uppercase font-semibold">
                          {item.status}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 text-right">
                        <div className="flex items-center justify-end gap-1.5">
                          <button
                            onClick={() => setSelectedVerifyEvidence(item)}
                            className="flex items-center gap-1 px-2 py-1 text-xs text-accent hover:bg-accent/10 border border-accent/30 rounded transition-colors"
                            title="Verify Cryptographic Hash"
                          >
                            <ShieldCheck className="h-3.5 w-3.5" />
                            Verify
                          </button>
                          <button
                            onClick={() => handleExport(item)}
                            disabled={exportingId !== null}
                            className="flex items-center gap-1.5 px-2.5 py-1 text-xs text-secondary hover:text-primary hover:bg-surface-elevated border border-border-subtle rounded transition-colors disabled:opacity-50"
                            title="Export Evidence Record"
                          >
                            {exportingId === item.evidence_id ? (
                              <Spinner size={12} />
                            ) : (
                              <Download className="h-3.5 w-3.5" />
                            )}
                            <span>{exportingId === item.evidence_id ? 'Exporting...' : 'Export'}</span>
                          </button>
                        </div>
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
      </div>

      {/* Custody Items List */}
      {custodyData && custodyData.items.length > 0 && (
        <div className="space-y-3 pt-4 border-t border-border-subtle">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-primary flex items-center gap-2">
              <Lock className="h-4 w-4 text-accent" />
              Custody Tracking Items ({custodyData.items.length})
            </h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {custodyData.items.map((cItem) => (
              <div key={cItem.evidence_item_id} className="border border-border-subtle rounded p-3.5 space-y-2 hover:bg-surface-elevated/30 transition-colors">
                <div className="flex justify-between items-start">
                  <div>
                    <p className="text-xs font-semibold text-primary">{cItem.label}</p>
                    <p className="text-[11px] text-muted font-mono">{cItem.evidence_type}</p>
                  </div>
                  <button
                    onClick={() => setSelectedCustodyItem(cItem)}
                    className="flex items-center gap-1 px-2 py-1 text-xs text-secondary hover:text-primary border border-border-subtle rounded hover:bg-surface-elevated transition-colors"
                  >
                    <Lock className="h-3 w-3 text-accent" />
                    Ledger
                  </button>
                </div>
                {cItem.description && <p className="text-xs text-secondary">{cItem.description}</p>}
                <p className="text-[10px] text-muted tabular-nums">Registered: {new Date(cItem.registered_at).toLocaleString()}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      <IntegrityVerificationModal evidence={selectedVerifyEvidence} onClose={() => setSelectedVerifyEvidence(null)} />
      <CustodyTimelineDrawer item={selectedCustodyItem} onClose={() => setSelectedCustodyItem(null)} />
    </div>
  );
}
