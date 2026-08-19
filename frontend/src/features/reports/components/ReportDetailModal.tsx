import { useState } from 'react';
import { FileText, X, ShieldCheck, Clock, Hash, Database, Copy, Check, Download, AlertTriangle, User } from 'lucide-react';
import type { ReportResponse } from '../types';
import { downloadReport } from '../api';
import { Button } from '../../../components/ui/Button';

interface ReportDetailModalProps {
  report: ReportResponse | null;
  onClose: () => void;
}

export function ReportDetailModal({ report, onClose }: ReportDetailModalProps) {
  const [copied, setCopied] = useState(false);
  const [downloadingFormat, setDownloadingFormat] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);

  if (!report) return null;

  const isValidSha256 =
    !!report.sha256 &&
    report.sha256 !== '0'.repeat(64) &&
    /^[a-fA-F0-9]{64}$/.test(report.sha256);

  const handleCopyHash = () => {
    if (report.sha256) {
      navigator.clipboard.writeText(report.sha256);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDownload = async (format: 'json' | 'pdf' | 'txt') => {
    setDownloadingFormat(format);
    setDownloadError(null);
    try {
      await downloadReport(report.report_id, format, report.title || undefined);
    } catch (err) {
      setDownloadError((err as Error).message || `Failed to export ${format.toUpperCase()} report.`);
    } finally {
      setDownloadingFormat(null);
    }
  };

  return (
    <>
      <div className="fixed inset-0 bg-black/60 z-40 backdrop-blur-sm transition-opacity" onClick={onClose} aria-hidden="true" />
      <div
        className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-2xl bg-surface border border-border-subtle rounded-2xl p-6 z-50 shadow-2xl space-y-5 overflow-hidden"
        role="dialog"
        aria-modal="true"
        aria-label="Report Detail"
      >
        {/* Header */}
        <div className="flex items-start justify-between pb-4 border-b border-border-subtle">
          <div className="flex items-center gap-3 min-w-0 pr-4">
            <div className="p-2.5 rounded-xl bg-accent/10 text-accent border border-accent/20 flex-shrink-0">
              <FileText className="h-5 w-5" aria-hidden="true" />
            </div>
            <div className="min-w-0 flex-1">
              <h2 className="text-base font-bold text-primary truncate" title={report.title || `Forensic Report v${report.version}`}>
                {report.title || `Forensic Report v${report.version}`}
              </h2>
              <p className="text-xs text-muted font-mono mt-0.5 truncate">
                Report ID: {report.report_id}
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="rounded-lg p-2 hover:bg-surface-elevated text-muted hover:text-primary transition-colors border border-transparent hover:border-border-subtle flex-shrink-0"
            aria-label="Close report detail"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Section 1: Overview Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 bg-surface-elevated/40 p-4 rounded-xl border border-border-subtle">
          <div>
            <span className="text-muted block text-[10px] uppercase font-semibold mb-1">Report Type</span>
            <span className="text-primary font-mono text-xs font-semibold uppercase bg-surface-elevated px-2.5 py-1 rounded-md border border-border-subtle inline-block truncate max-w-full" title={report.report_type}>
              {report.report_type}
            </span>
          </div>
          <div>
            <span className="text-muted block text-[10px] uppercase font-semibold mb-1">Format & Version</span>
            <span className="text-primary font-mono text-xs font-semibold">
              {report.format.toUpperCase()} (v{report.version})
            </span>
          </div>
          <div>
            <span className="text-muted block text-[10px] uppercase font-semibold mb-1 flex items-center gap-1">
              <Clock className="h-3 w-3 text-accent" /> Generated
            </span>
            <span className="text-secondary font-mono text-xs">
              {new Date(report.generated_at).toLocaleString()}
            </span>
          </div>
          <div>
            <span className="text-muted block text-[10px] uppercase font-semibold mb-1 flex items-center gap-1">
              <User className="h-3 w-3 text-accent" /> Author
            </span>
            <span className="text-secondary font-mono text-xs truncate block" title={report.generated_by || 'System Automated Engine'}>
              {report.generated_by || 'System Engine'}
            </span>
          </div>
        </div>

        {/* Section 2: SHA-256 Digest & Storage Reference Cards */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* SHA-256 Card */}
          <div className="bg-surface-elevated/40 p-4 rounded-xl border border-border-subtle space-y-2 flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <span className="text-muted text-[10px] uppercase font-semibold flex items-center gap-1.5">
                <Hash className="h-3.5 w-3.5 text-accent" /> SHA-256 Cryptographic Hash
              </span>
              <button
                onClick={handleCopyHash}
                className="flex items-center gap-1 text-xs text-accent hover:text-accent/80 font-medium transition-colors"
                title="Copy SHA-256 hash"
              >
                {copied ? (
                  <><Check className="h-3.5 w-3.5 text-success" /> <span className="text-success font-semibold">Copied</span></>
                ) : (
                  <><Copy className="h-3.5 w-3.5" /> Copy</>
                )}
              </button>
            </div>
            <p className="text-[11px] font-mono text-primary break-all bg-background p-2.5 rounded-lg border border-border-subtle select-all leading-relaxed shadow-inner">
              {report.sha256 || 'N/A'}
            </p>
          </div>

          {/* Storage & Verification Card */}
          <div className="bg-surface-elevated/40 p-4 rounded-xl border border-border-subtle space-y-3 flex flex-col justify-between">
            <div>
              <span className="text-muted block text-[10px] uppercase font-semibold mb-1 flex items-center gap-1.5">
                <Database className="h-3.5 w-3.5 text-accent" /> Storage Reference
              </span>
              <p className="text-xs font-mono text-secondary truncate bg-background p-2 rounded-lg border border-border-subtle" title={`${report.minio_bucket} / ${report.object_key}`}>
                {report.minio_bucket} / {report.object_key}
              </p>
            </div>

            {isValidSha256 ? (
              <div className="flex items-center gap-2.5 p-2 rounded-lg bg-success/10 border border-success/30 text-xs">
                <ShieldCheck className="h-4 w-4 text-success flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="font-semibold text-success text-xs flex items-center gap-2">
                    Integrity Verified
                    <span className="text-[9px] font-mono bg-success/20 text-success px-1.5 py-0.2 rounded uppercase font-bold">
                      PASS
                    </span>
                  </p>
                  <p className="text-muted text-[10px] truncate">
                    Checksum matches storage manifest.
                  </p>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2.5 p-2 rounded-lg bg-danger/10 border border-danger/30 text-xs">
                <AlertTriangle className="h-4 w-4 text-danger flex-shrink-0" />
                <div className="flex-1 min-w-0">
                  <p className="font-semibold text-danger text-xs flex items-center gap-2">
                    Integrity Unverified
                    <span className="text-[9px] font-mono bg-danger/20 text-danger px-1.5 py-0.2 rounded uppercase font-bold">
                      UNVERIFIED
                    </span>
                  </p>
                  <p className="text-muted text-[10px] truncate">
                    Invalid or all-zero SHA-256 hash.
                  </p>
                </div>
              </div>
            )}
          </div>
        </div>

        {downloadError && (
          <div className="p-3 rounded-xl bg-danger/10 border border-danger/30 text-xs text-danger flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 flex-shrink-0" />
            <span>{downloadError}</span>
          </div>
        )}

        {/* Section 3: Action Buttons Bar */}
        <div className="pt-4 border-t border-border-subtle flex items-center justify-between gap-4">
          <div className="flex items-center gap-2.5">
            <Button
              variant="secondary"
              onClick={() => handleDownload('json')}
              disabled={!!downloadingFormat}
              className="text-xs py-2 px-3.5 flex items-center justify-center gap-1.5 border-border-subtle hover:bg-surface-elevated"
            >
              <Download className="h-3.5 w-3.5 text-accent" />
              {downloadingFormat === 'json' ? 'Exporting...' : 'Export JSON'}
            </Button>
            <Button
              variant="secondary"
              onClick={() => handleDownload('pdf')}
              disabled={!!downloadingFormat}
              className="text-xs py-2 px-3.5 flex items-center justify-center gap-1.5 border-border-subtle hover:bg-surface-elevated"
            >
              <Download className="h-3.5 w-3.5 text-accent" />
              {downloadingFormat === 'pdf' ? 'Exporting...' : 'Export PDF'}
            </Button>
            <Button
              variant="secondary"
              onClick={() => handleDownload('txt')}
              disabled={!!downloadingFormat}
              className="text-xs py-2 px-3.5 flex items-center justify-center gap-1.5 border-border-subtle hover:bg-surface-elevated"
            >
              <Download className="h-3.5 w-3.5 text-accent" />
              {downloadingFormat === 'txt' ? 'Exporting...' : 'Export TXT'}
            </Button>
          </div>
          <Button
            variant="ghost"
            onClick={onClose}
            className="px-5 py-2 text-xs font-semibold text-secondary hover:text-primary border border-border-subtle hover:bg-surface-elevated flex-shrink-0"
          >
            Close
          </Button>
        </div>
      </div>
    </>
  );
}
