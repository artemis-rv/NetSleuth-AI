import { ShieldCheck, AlertTriangle, X, CheckCircle2, RefreshCw } from 'lucide-react';
import { useVerifyEvidenceMutation } from '../hooks';
import type { EvidenceResponse, EvidenceVerificationResponse } from '../types';
import { useState } from 'react';

interface IntegrityVerificationModalProps {
  evidence: EvidenceResponse | null;
  onClose: () => void;
}

export function IntegrityVerificationModal({ evidence, onClose }: IntegrityVerificationModalProps) {
  const [result, setResult] = useState<EvidenceVerificationResponse | null>(null);
  const verifyMutation = useVerifyEvidenceMutation();

  if (!evidence) return null;

  function handleVerify() {
    verifyMutation.mutate(evidence!.evidence_id, {
      onSuccess: (res) => setResult(res),
    });
  }

  const isMismatch = result?.integrity_status?.toLowerCase() === 'mismatch';
  const isVerified = result?.integrity_status?.toLowerCase() === 'verified' || result?.integrity_status?.toLowerCase() === 'valid' || result?.integrity_status?.toLowerCase() === 'match';

  return (
    <>
      <div className="fixed inset-0 bg-black/50 z-40 backdrop-blur-sm" onClick={onClose} aria-hidden="true" />
      <div
        className="fixed left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 w-full max-w-lg bg-surface border border-border-subtle rounded-lg p-6 z-50 shadow-2xl space-y-5"
        role="dialog"
        aria-modal="true"
        aria-label="Evidence Integrity Verification"
      >
        {/* Header */}
        <div className="flex items-center justify-between pb-3 border-b border-border-subtle">
          <div className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-accent" aria-hidden="true" />
            <h2 className="text-base font-semibold text-primary">Integrity Verification</h2>
          </div>
          <button
            onClick={onClose}
            className="rounded p-1 hover:bg-surface-elevated text-muted hover:text-primary transition-colors"
            aria-label="Close modal"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        {/* Evidence Metadata */}
        <div className="space-y-2 bg-surface-elevated/40 p-3.5 rounded border border-border-subtle text-xs">
          <div className="flex justify-between">
            <span className="text-muted">Filename:</span>
            <span className="text-primary font-mono font-medium">{evidence.file_name}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted">Evidence ID:</span>
            <span className="text-primary font-mono">{evidence.evidence_id}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted">Registered SHA-256:</span>
            <span className="text-primary font-mono truncate max-w-[240px]" title={evidence.sha256}>
              {evidence.sha256}
            </span>
          </div>
        </div>

        {/* Verification Status */}
        {verifyMutation.isPending && (
          <div className="flex items-center justify-center py-6 text-sm text-secondary gap-2">
            <RefreshCw className="h-4 w-4 animate-spin text-accent" />
            Computing cryptographic hash verification...
          </div>
        )}

        {result && (
          <div className="space-y-3">
            {isMismatch ? (
              <div className="p-4 rounded border border-red-500/50 bg-red-500/10 text-red-300 space-y-2">
                <div className="flex items-center gap-2 font-semibold text-sm">
                  <AlertTriangle className="h-5 w-5 text-red-400" />
                  HASH MISMATCH DETECTED
                </div>
                <p className="text-xs text-red-200/90 leading-relaxed">
                  The observed hash does not match the registered hash. Evidence integrity may be compromised.
                </p>
              </div>
            ) : isVerified ? (
              <div className="p-4 rounded border border-green-500/50 bg-green-500/10 text-green-300 space-y-2">
                <div className="flex items-center gap-2 font-semibold text-sm">
                  <CheckCircle2 className="h-5 w-5 text-green-400" />
                  Integrity Verified
                </div>
                <p className="text-xs text-green-200/90 leading-relaxed">
                  Cryptographic SHA-256 hash matches original registration record.
                </p>
              </div>
            ) : (
              <div className="p-4 rounded border border-yellow-500/50 bg-yellow-500/10 text-yellow-300 space-y-2">
                <div className="flex items-center gap-2 font-semibold text-sm">
                  <AlertTriangle className="h-5 w-5 text-yellow-400" />
                  Status: {result.integrity_status}
                </div>
              </div>
            )}

            {/* Comparison detail */}
            <div className="space-y-1.5 p-3 rounded bg-surface-elevated border border-border-subtle text-xs font-mono">
              <div>
                <span className="text-muted block text-[10px] uppercase">Expected SHA-256</span>
                <span className="text-primary break-all">{result.expected_sha256}</span>
              </div>
              {result.observed_sha256 && (
                <div className="pt-1.5 border-t border-border-subtle">
                  <span className="text-muted block text-[10px] uppercase">Observed SHA-256</span>
                  <span className={isMismatch ? 'text-red-400 font-bold break-all' : 'text-green-400 break-all'}>
                    {result.observed_sha256}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}

        {verifyMutation.isError && (
          <div className="p-3 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-xs">
            Failed to perform verification: {(verifyMutation.error as Error)?.message}
          </div>
        )}

        {/* Footer actions */}
        <div className="flex justify-end gap-2 pt-2 border-t border-border-subtle">
          <button
            onClick={onClose}
            className="px-3.5 py-1.5 text-xs text-secondary hover:text-primary border border-border-subtle rounded hover:bg-surface-elevated transition-colors"
          >
            Close
          </button>
          {!result && (
            <button
              onClick={handleVerify}
              disabled={verifyMutation.isPending}
              className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs bg-accent text-white rounded hover:bg-accent/90 disabled:opacity-50 font-medium transition-colors"
            >
              <ShieldCheck className="h-3.5 w-3.5" />
              Verify Cryptographic Hash
            </button>
          )}
        </div>
      </div>
    </>
  );
}
