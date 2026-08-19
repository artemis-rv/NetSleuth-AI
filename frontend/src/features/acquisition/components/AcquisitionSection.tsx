import { useState, useRef } from 'react';
import { Upload, File as FileIcon, AlertCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../../components/ui/Card';
import { Button } from '../../../components/ui/Button';
import { Badge } from '../../../components/ui/Badge';
import { Spinner } from '../../../components/ui/Spinner';
import { useUploadAcquisition, useVerifyEvidence } from '../hooks';
import { useStartAnalysis } from '../../analysis/hooks';
import { EvidenceVerificationBadge } from './EvidenceVerificationBadge';
import type { AcquisitionResponse, EvidenceResponse } from '../types';
import { ApiError } from '../../../api/errors';

interface AcquisitionSectionProps {
  caseId: string;
  acquisitions: AcquisitionResponse[];
  evidenceList: EvidenceResponse[];
}

export function AcquisitionSection({ caseId, acquisitions, evidenceList }: AcquisitionSectionProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);
  const [analyzingAcqId, setAnalyzingAcqId] = useState<string | null>(null);

  const uploadMutation = useUploadAcquisition(caseId);
  const verifyMutation = useVerifyEvidence();
  const startAnalysisMutation = useStartAnalysis(caseId);

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const files = Array.from(e.target.files);
      const totalSize = files.reduce((acc, f) => acc + f.size, 0);
      
      if (totalSize > 5 * 1024 * 1024 * 1024) {
        setErrorMsg('Total file size exceeds the 5GB limit.');
        setSelectedFiles([]);
        return;
      }
      setSelectedFiles(files);
      setErrorMsg(null);
    }
  };

  const handleUpload = () => {
    if (selectedFiles.length === 0) return;
    setErrorMsg(null);
    uploadMutation.mutate(selectedFiles, {
      onSuccess: () => {
        setSelectedFiles([]);
        if (fileInputRef.current) {
          fileInputRef.current.value = '';
        }
      },
      onError: (error) => {
        const msg = error instanceof ApiError ? error.message : 'Upload failed. Please try again.';
        setErrorMsg(msg);
      },
    });
  };

  const handleVerify = (evidenceId: string) => {
    verifyMutation.mutate(evidenceId, {
      onError: (error) => {
        const msg = error instanceof ApiError ? error.message : 'Verification request failed.';
        setErrorMsg(msg);
      }
    });
  };

  const handleStartAnalysis = (acquisitionId: string) => {
    setAnalyzingAcqId(acquisitionId);
    startAnalysisMutation.mutate(acquisitionId, {
      onSettled: () => setAnalyzingAcqId(null),
      onError: (error) => {
        const msg = error instanceof ApiError ? error.message : 'Failed to start analysis.';
        setErrorMsg(msg);
      }
    });
  };

  const isUploading = uploadMutation.isPending;
  const totalFilesSize = selectedFiles.reduce((acc, f) => acc + f.size, 0);

  return (
    <Card className="flex flex-col h-full border-border-subtle bg-surface-elevated/30">
      <CardHeader className="pb-2 border-b border-border-subtle/50 px-5 pt-5 mb-4 flex flex-row items-center justify-between">
        <CardTitle className="text-sm flex items-center gap-2">
          <Upload className="h-4 w-4 text-accent" aria-hidden="true" />
          Evidence Acquisitions
        </CardTitle>
        {acquisitions.length > 0 && (
          <Button variant="secondary" size="sm" onClick={() => fileInputRef.current?.click()} className="h-7 text-xs">
            Upload More
          </Button>
        )}
      </CardHeader>
      <CardContent className="px-5 py-4 flex-1">
        {/* Upload Dropzone */}
        {(acquisitions.length === 0 || selectedFiles.length > 0) && (
          <div className="flex flex-col items-center justify-center p-6 border-2 border-dashed border-border-subtle/50 rounded-lg bg-surface/50 mb-5 transition-colors hover:bg-surface">
            <Upload className="h-10 w-10 text-muted mb-4" />
            <p className="text-sm text-primary mb-2">Upload PCAP or PCAPNG captures to begin analysis.</p>
            <p className="text-xs text-muted mb-6">Select multiple valid network capture files.</p>
            
            <input 
              type="file" 
              multiple
              ref={fileInputRef}
              onChange={handleFileSelect}
              className="hidden"
              accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/x-pcapng"
              aria-label="Select PCAP files"
            />
            
            {selectedFiles.length === 0 ? (
              <Button onClick={() => fileInputRef.current?.click()} variant="secondary">
                Select Files
              </Button>
            ) : (
              <div className="w-full max-w-lg">
                <div className="flex items-center justify-between bg-background p-3 rounded border border-border-subtle mb-4">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <FileIcon className="h-5 w-5 text-accent flex-shrink-0" />
                    <div className="truncate">
                      <p className="text-sm font-medium text-primary truncate">
                        {selectedFiles.length} file{selectedFiles.length !== 1 ? 's' : ''} selected
                      </p>
                      <p className="text-xs text-muted">{(totalFilesSize / (1024 * 1024)).toFixed(2)} MB total</p>
                    </div>
                  </div>
                  <div className="flex gap-2">
                    <Button 
                      variant="ghost" 
                      size="sm" 
                      onClick={() => {
                        setSelectedFiles([]);
                        setErrorMsg(null);
                        if (fileInputRef.current) fileInputRef.current.value = '';
                      }}
                      disabled={isUploading}
                    >
                      Cancel
                    </Button>
                    <Button 
                      variant="secondary" 
                      size="sm" 
                      onClick={handleUpload}
                      disabled={isUploading}
                    >
                      {isUploading ? <><Spinner size={14} className="mr-2" /> Uploading...</> : 'Upload All'}
                    </Button>
                  </div>
                </div>
                {uploadMutation.isError && errorMsg && (
                  <div className="flex items-start gap-2 text-sm text-danger mt-2 bg-danger/10 p-2 rounded">
                    <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                    <p>{errorMsg}</p>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Existing Acquisitions List */}
        {acquisitions.length > 0 && (
          <div className="space-y-2.5">
            <h3 className="text-[11px] uppercase tracking-wider text-muted font-semibold mb-2">Uploaded Evidence</h3>
            {acquisitions.map(acq => {
              const ev = evidenceList.find(e => e.acquisition_id === acq.acquisition_id);
              return (
                <div key={acq.acquisition_id} className="border border-border-subtle rounded-md p-3 bg-surface/80 hover:bg-surface-elevated/50 transition-colors flex flex-col xl:flex-row xl:items-center gap-3">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3">
                      <FileIcon className="h-4 w-4 text-accent flex-shrink-0" />
                      <div className="truncate flex-1">
                        <div className="flex items-center gap-2">
                          <p className="text-[13px] font-medium text-primary truncate">{acq.file_name}</p>
                          <Badge variant={acq.status === 'complete' ? 'success' : acq.status === 'failed' ? 'danger' : 'warning'} className="text-[10px] px-1.5 py-0 h-4">
                            {acq.status}
                          </Badge>
                        </div>
                        <div className="flex flex-wrap items-center gap-3 mt-1.5">
                          <p className="text-[11px] text-muted">
                            {(acq.file_size / (1024 * 1024)).toFixed(2)} MB
                          </p>
                          <p className="text-[11px] text-muted">
                            {new Date(acq.ingested_at).toLocaleString()}
                          </p>
                          {ev && (
                            <div className="flex items-center gap-2 border-l border-border-subtle pl-3 ml-1">
                              <EvidenceVerificationBadge status={ev.integrity_status} />
                              <span className="font-mono text-muted text-[10px] truncate max-w-[120px]" title={ev.sha256}>
                                {ev.sha256.substring(0, 16)}...
                              </span>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  <div className="flex justify-end gap-2 shrink-0">
                    {ev && ev.integrity_status === 'pending' && (
                      <Button 
                        variant="secondary" 
                        size="sm"
                        onClick={() => handleVerify(ev.evidence_id)}
                        disabled={verifyMutation.isPending}
                        className="h-7 text-xs"
                      >
                        {verifyMutation.isPending ? <Spinner size={12} /> : 'Verify'}
                      </Button>
                    )}
                    <Button 
                      variant="primary" 
                      size="sm"
                      onClick={() => handleStartAnalysis(acq.acquisition_id)}
                      disabled={analyzingAcqId === acq.acquisition_id || acq.status !== 'complete'}
                      className="h-7 text-xs"
                    >
                      {analyzingAcqId === acq.acquisition_id ? (
                        <><Spinner size={12} className="mr-1" /> Analyzing...</>
                      ) : (
                        'Start Analysis'
                      )}
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}

        {/* Global errors */}
        {!isUploading && errorMsg && acquisitions.length > 0 && selectedFiles.length === 0 && (
          <div className="flex items-start gap-2 text-sm text-danger mt-3 bg-danger/10 p-2 rounded">
            <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
            <p>{errorMsg}</p>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
