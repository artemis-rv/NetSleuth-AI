import { useState, useRef } from 'react';
import { Upload, File as FileIcon, AlertCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../../components/ui/Card';
import { Button } from '../../../components/ui/Button';
import { Badge } from '../../../components/ui/Badge';
import { Spinner } from '../../../components/ui/Spinner';
import { useUploadAcquisition, useVerifyEvidence } from '../hooks';
import { useStartAnalysis } from '../../analysis/hooks';
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
  const [verifyingEvId, setVerifyingEvId] = useState<string | null>(null);

  const uploadMutation = useUploadAcquisition(caseId);
  const verifyMutation = useVerifyEvidence();
  const startAnalysisMutation = useStartAnalysis(caseId);

  const handleStartAnalysis = (acqId: string) => {
    setAnalyzingAcqId(acqId);
    startAnalysisMutation.mutate(acqId, {
      onSettled: () => setAnalyzingAcqId(null),
      onError: (error) => {
        const msg = error instanceof ApiError ? error.message : 'Failed to start analysis.';
        setErrorMsg(msg);
      }
    });
  };

  const handleVerify = (evId: string) => {
    setVerifyingEvId(evId);
    verifyMutation.mutate(evId, {
      onSettled: () => setVerifyingEvId(null),
      onError: (error) => {
        const msg = error instanceof ApiError ? error.message : 'Verification request failed.';
        setErrorMsg(msg);
      }
    });
  };

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

  const isUploading = uploadMutation.isPending;
  const totalFilesSize = selectedFiles.reduce((acc, f) => acc + f.size, 0);

  return (
    <Card>
      <CardHeader className="pb-3 border-b border-border-subtle mb-4 flex flex-row items-center justify-between">
        <CardTitle className="text-base flex items-center gap-2">
          <Upload className="h-5 w-5 text-accent" aria-hidden="true" />
          Evidence Acquisitions
        </CardTitle>
        {acquisitions.length > 0 && (
          <Button variant="secondary" size="sm" onClick={() => fileInputRef.current?.click()}>
            Upload More
          </Button>
        )}
      </CardHeader>
      <CardContent>
        {/* Upload Dropzone */}
        {(acquisitions.length === 0 || selectedFiles.length > 0) && (
          <div className="flex flex-col items-center justify-center p-8 border-2 border-dashed border-border-subtle rounded-lg bg-surface-elevated mb-6">
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
          <div className="space-y-4">
            <h3 className="text-sm font-medium text-primary">Uploaded Evidence</h3>
            {acquisitions.map(acq => {
              const ev = evidenceList.find(e => e.acquisition_id === acq.acquisition_id);
              return (
                <div key={acq.acquisition_id} className="border border-border-subtle rounded-lg p-4 bg-surface-elevated flex flex-col sm:flex-row gap-4">
                  <div className="flex-1 space-y-4">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-3">
                        <div className="p-2 bg-background rounded border border-border-subtle">
                          <FileIcon className="h-6 w-6 text-accent" />
                        </div>
                        <div>
                          <p className="text-sm font-medium text-primary break-all">{acq.file_name}</p>
                          <p className="text-xs text-muted">
                            Size: {(acq.file_size / (1024 * 1024)).toFixed(2)} MB | Ingested: {new Date(acq.ingested_at).toLocaleString()}
                          </p>
                        </div>
                      </div>
                      <Badge variant={acq.status === 'complete' ? 'success' : acq.status === 'failed' ? 'danger' : 'warning'}>
                        {acq.status.toUpperCase()}
                      </Badge>
                    </div>

                    {ev && (
                      <div className="bg-background p-3 rounded border border-border-subtle space-y-2 text-xs">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-muted">SHA-256 Hash</span>
                          <Badge variant={ev.status === 'verified' ? 'success' : 'warning'} className="text-[10px]">
                            {ev.status.toUpperCase()}
                          </Badge>
                        </div>
                        <p className="font-mono text-primary break-all bg-surface p-1.5 rounded text-[11px]">
                          {ev.sha256}
                        </p>
                      </div>
                    )}
                  </div>

                  <div className="flex sm:flex-col justify-end gap-2 border-t sm:border-t-0 sm:border-l border-border-subtle pt-3 sm:pt-0 sm:pl-4 min-w-[140px]">
                    <Button 
                      variant="primary" 
                      size="sm"
                      onClick={() => handleStartAnalysis(acq.acquisition_id)}
                      disabled={analyzingAcqId === acq.acquisition_id || acq.status !== 'complete'}
                      className="w-full"
                    >
                      {analyzingAcqId === acq.acquisition_id ? (
                        <><Spinner size={12} className="mr-1" /> Analyzing...</>
                      ) : (
                        'Start Analysis'
                      )}
                    </Button>
                    
                    {ev && ev.status !== 'verified' && (
                      <Button 
                        variant="secondary" 
                        size="sm"
                        onClick={() => handleVerify(ev.evidence_id)}
                        disabled={verifyingEvId === ev.evidence_id}
                        className="w-full"
                      >
                        {verifyingEvId === ev.evidence_id ? <Spinner size={12} /> : 'Verify Hash'}
                      </Button>
                    )}
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
