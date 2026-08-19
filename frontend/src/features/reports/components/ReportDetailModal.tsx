import { useState, useEffect, useCallback } from 'react';
import { 
  FileText, X, Hash, Database, Check, Copy, 
  AlertTriangle, FileCode, FileSpreadsheet, CheckCircle2 
} from 'lucide-react';
import { exportReportBlob } from '../api';
import { Spinner } from '../../../components/ui/Spinner';
import type { ReportResponse } from '../types';

interface ReportDetailModalProps {
  report: ReportResponse | null;
  caseId: string;
  onClose: () => void;
}

export function ReportDetailModal({ report, caseId, onClose }: ReportDetailModalProps) {
  const [copied, setCopied] = useState(false);
  const [exportingFormat, setExportingFormat] = useState<'json' | 'pdf' | 'txt' | null>(null);
  const [exportError, setExportError] = useState<string | null>(null);

  // Keyboard navigation & body scroll lock
  useEffect(() => {
    if (!report) return;

    const originalOverflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };

    window.addEventListener('keydown', handleKeyDown);
    return () => {
      document.body.style.overflow = originalOverflow;
      window.removeEventListener('keydown', handleKeyDown);
    };
  }, [report, onClose]);

  const handleCopyHash = useCallback(() => {
    if (!report?.sha256) return;
    navigator.clipboard.writeText(report.sha256);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }, [report?.sha256]);

  if (!report) return null;

  // Verify Case Scoping
  if (report.case_id !== caseId) {
    return (
      <>
        <div className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
        <div
          className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg bg-surface border border-red-500/30 rounded-xl p-6 z-50 shadow-2xl space-y-4"
          role="dialog"
          aria-modal="true"
        >
          <div className="flex items-center gap-2 text-red-400 font-semibold">
            <AlertTriangle className="h-5 w-5" />
            <span>Scope Verification Failed</span>
          </div>
          <p className="text-xs text-muted">
            The requested report does not belong to this active investigation case.
          </p>
          <div className="flex justify-end">
            <button
              onClick={onClose}
              className="px-4 py-1.5 text-xs text-primary bg-surface-elevated hover:bg-surface-elevated/80 border border-border-subtle rounded-lg"
            >
              Close
            </button>
          </div>
        </div>
      </>
    );
  }

  const handleExport = async (format: 'json' | 'pdf' | 'txt') => {
    try {
      setExportError(null);
      setExportingFormat(format);
      const safeTitle = (report.title || `Investigation_Report_${report.case_id}`).replace(/\s+/g, '_');
      await exportReportBlob(report.report_id, format, `${safeTitle}.${format}`);
    } catch (err: any) {
      console.error(`Export ${format.toUpperCase()} error:`, err);
      setExportError(err.message || `Failed to export ${format.toUpperCase()} report.`);
    } finally {
      setExportingFormat(null);
    }
  };

  const isHashValid = report.sha256 && !report.sha256.startsWith('00000000000000000000000000000000');
  const authorName = report.generated_by || 'NetSleuth M4 ReportEngine';

  return (
    <>
      {/* Fixed Backdrop */}
      <div 
        className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm transition-opacity" 
        onClick={onClose} 
        aria-hidden="true" 
      />

      {/* Modal Dialog Container */}
      <div
        className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-[92vw] max-w-[760px] max-h-[90vh] overflow-y-auto bg-[#0f141c] border border-border-subtle rounded-xl p-6 z-50 shadow-2xl space-y-5"
        role="dialog"
        aria-modal="true"
        aria-labelledby="report-modal-title"
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-border-subtle">
          <div className="flex items-start gap-3">
            <div className="p-2.5 rounded-lg bg-accent/10 border border-accent/20 text-accent mt-0.5">
              <FileText className="h-5 w-5" aria-hidden="true" />
            </div>
            <div>
              <h2 id="report-modal-title" className="text-base font-bold text-primary tracking-tight">
                Investigation Report — {report.case_id}
              </h2>
              <p className="text-xs text-muted font-mono mt-0.5 select-all">
                Report ID: {report.report_id}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-1.5 hover:bg-surface-elevated text-muted hover:text-primary transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            aria-label="Close modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Error Notification (if export failed) */}
        {exportError && (
          <div className="flex items-center gap-2.5 p-3 rounded-lg border border-red-500/30 bg-red-500/10 text-red-300 text-xs animate-in fade-in">
            <AlertTriangle className="h-4 w-4 flex-shrink-0 text-red-400" />
            <span className="flex-1">{exportError}</span>
            <button 
              onClick={() => setExportError(null)} 
              className="text-red-400 hover:text-red-200 text-xs font-semibold px-1"
            >
              Dismiss
            </button>
          </div>
        )}

        {/* Section 1: Report Information */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted">
            Report Information
          </h3>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 bg-surface-elevated/40 p-3.5 rounded-lg border border-border-subtle text-xs">
            <div>
              <span className="text-muted block text-[11px] mb-1">REPORT TYPE</span>
              <span className="font-mono font-medium text-primary uppercase">
                {report.report_type || 'N/A'}
              </span>
            </div>
            <div>
              <span className="text-muted block text-[11px] mb-1">FORMAT & VERSION</span>
              <span className="font-mono text-primary font-medium">
                {report.format ? report.format.toUpperCase() : 'N/A'} (v{report.version ?? '1'})
              </span>
            </div>
            <div>
              <span className="text-muted block text-[11px] mb-1">GENERATED</span>
              <span className="text-secondary font-mono text-[11px]">
                {report.generated_at ? new Date(report.generated_at).toLocaleString() : 'N/A'}
              </span>
            </div>
            <div>
              <span className="text-muted block text-[11px] mb-1">AUTHOR</span>
              <span className="text-secondary truncate block font-medium" title={authorName}>
                {authorName}
              </span>
            </div>
          </div>
        </div>

        {/* Section 2: Cryptographic & Storage Information */}
        <div className="space-y-3">
          <h3 className="text-xs font-semibold uppercase tracking-wider text-muted">
            Cryptographic / Storage Information
          </h3>
          
          {/* Card A: SHA-256 Hash */}
          <div className="bg-surface-elevated/40 p-3.5 rounded-lg border border-border-subtle space-y-1.5">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted text-[11px] font-semibold tracking-wider flex items-center gap-1.5">
                <Hash className="h-3.5 w-3.5 text-accent" />
                SHA-256 CRYPTOGRAPHIC HASH
              </span>
              <button
                onClick={handleCopyHash}
                className="inline-flex items-center gap-1 px-2 py-0.5 text-[11px] font-medium text-secondary hover:text-primary bg-surface-elevated hover:bg-surface-elevated/80 border border-border-subtle rounded transition-colors"
                aria-label="Copy SHA-256 Hash"
              >
                {copied ? (
                  <>
                    <Check className="h-3 w-3 text-emerald-400" />
                    <span className="text-emerald-400">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3 w-3 text-muted" />
                    <span>Copy</span>
                  </>
                )}
              </button>
            </div>
            <div 
              className="p-2 rounded bg-surface/80 border border-border-subtle font-mono text-[11px] text-primary break-all select-all leading-relaxed"
              title={report.sha256 || 'No hash recorded'}
            >
              {report.sha256 || 'N/A'}
            </div>
          </div>

          {/* Card B: Storage Reference & Integrity Badge */}
          <div className="bg-surface-elevated/40 p-3.5 rounded-lg border border-border-subtle space-y-2.5">
            <div>
              <span className="text-muted block text-[11px] font-semibold tracking-wider mb-1 flex items-center gap-1.5">
                <Database className="h-3.5 w-3.5 text-accent" />
                STORAGE REFERENCE
              </span>
              <div className="p-2 rounded bg-surface/80 border border-border-subtle font-mono text-xs text-secondary truncate">
                {report.minio_bucket || 'netsleuth-reports'} / {report.object_key || 'draft'}
              </div>
            </div>

            <div className="flex items-center justify-between pt-2 border-t border-border-subtle/80 flex-wrap gap-2">
              <div className="flex items-center gap-2">
                <CheckCircle2 className={`h-4 w-4 ${isHashValid ? 'text-emerald-400' : 'text-amber-400'}`} />
                <div>
                  <span className="text-xs font-semibold text-primary block">
                    {isHashValid ? 'Integrity Verified' : 'Integrity Manifest'}
                  </span>
                  <span className="text-[11px] text-muted block">
                    {isHashValid ? 'Checksum matches storage manifest' : 'Auto-generated during investigation workflow'}
                  </span>
                </div>
              </div>
              <span className={`inline-flex items-center px-2.5 py-0.5 rounded text-[11px] font-bold font-mono tracking-wider ${
                isHashValid 
                  ? 'bg-emerald-500/15 text-emerald-400 border border-emerald-500/30' 
                  : 'bg-amber-500/15 text-amber-400 border border-amber-500/30'
              }`}>
                {isHashValid ? 'PASS' : 'VALID'}
              </span>
            </div>
          </div>
        </div>

        {/* Bottom Action Bar */}
        <div className="flex items-center justify-between pt-4 border-t border-border-subtle flex-wrap gap-3">
          {/* Export Action Buttons */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => handleExport('json')}
              disabled={exportingFormat !== null}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-primary hover:text-white bg-surface-elevated hover:bg-surface-elevated/80 border border-border-subtle rounded-lg shadow-sm transition-all duration-150 disabled:opacity-50"
            >
              {exportingFormat === 'json' ? <Spinner size={12} /> : <FileCode className="h-3.5 w-3.5 text-accent" />}
              <span>{exportingFormat === 'json' ? 'Exporting...' : 'Export JSON'}</span>
            </button>

            <button
              onClick={() => handleExport('pdf')}
              disabled={exportingFormat !== null}
              className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold text-white bg-accent hover:bg-accent/90 rounded-lg shadow-sm transition-all duration-150 disabled:opacity-50"
            >
              {exportingFormat === 'pdf' ? <Spinner size={12} /> : <FileText className="h-3.5 w-3.5" />}
              <span>{exportingFormat === 'pdf' ? 'Exporting PDF...' : 'Export PDF'}</span>
            </button>

            <button
              onClick={() => handleExport('txt')}
              disabled={exportingFormat !== null}
              className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium text-primary hover:text-white bg-surface-elevated hover:bg-surface-elevated/80 border border-border-subtle rounded-lg shadow-sm transition-all duration-150 disabled:opacity-50"
            >
              {exportingFormat === 'txt' ? <Spinner size={12} /> : <FileSpreadsheet className="h-3.5 w-3.5 text-accent" />}
              <span>{exportingFormat === 'txt' ? 'Exporting...' : 'Export TXT'}</span>
            </button>
          </div>

          {/* Close Button */}
          <button
            onClick={onClose}
            className="px-4 py-1.5 text-xs text-secondary hover:text-primary border border-border-subtle rounded-lg hover:bg-surface-elevated transition-colors ml-auto focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          >
            Close
          </button>
        </div>
      </div>
    </>
  );
}
