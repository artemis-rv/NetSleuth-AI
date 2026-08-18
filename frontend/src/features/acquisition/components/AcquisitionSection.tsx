import { useState, useRef } from 'react';
import { Upload, File as FileIcon, Shield, AlertCircle } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../../components/ui/Card';
import { Button } from '../../../components/ui/Button';
import { Badge } from '../../../components/ui/Badge';
import { Spinner } from '../../../components/ui/Spinner';
import { useUploadAcquisition, useVerifyEvidence } from '../hooks';
import { EvidenceVerificationBadge } from './EvidenceVerificationBadge';
import type { AcquisitionResponse, EvidenceResponse } from '../types';
import { ApiError } from '../../../api/errors';

interface AcquisitionSectionProps {
  caseId: string;
  acquisition: AcquisitionResponse | undefined;
  evidence: EvidenceResponse | undefined;
}

export function AcquisitionSection({ caseId, acquisition, evidence }: AcquisitionSectionProps) {
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const uploadMutation = useUploadAcquisition(caseId);
  const verifyMutation = useVerifyEvidence();

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      // Size limit on FE (assume ~1GB max for demo, though backend is authority)
      if (file.size > 1024 * 1024 * 1024) {
        setErrorMsg('File size exceeds the 1GB frontend limit. Contact administrator for larger files.');
        setSelectedFile(null);
        return;
      }
      setSelectedFile(file);
      setErrorMsg(null);
    }
  };

  const handleUpload = () => {
    if (!selectedFile) return;
    setErrorMsg(null);
    uploadMutation.mutate(selectedFile, {
      onSuccess: () => {
        setSelectedFile(null);
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

  const handleVerify = () => {
    if (!evidence) return;
    verifyMutation.mutate(evidence.evidence_id, {
      onError: (error) => {
        // Validation/Verification errors are often 400s or handled by updating status to 'mismatch'
        // If it's a hard network error we show it
        const msg = error instanceof ApiError ? error.message : 'Verification request failed.';
        setErrorMsg(msg);
      }
    });
  };

  const isUploading = uploadMutation.isPending;
  const isVerifying = verifyMutation.isPending;

  // Render Upload UI if no acquisition exists
  if (!acquisition) {
    return (
      <Card>
        <CardHeader className="pb-3 border-b border-border-subtle mb-4">
          <CardTitle className="text-base flex items-center gap-2">
            <Upload className="h-5 w-5 text-accent" aria-hidden="true" />
            Evidence Acquisition
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center p-8 border-2 border-dashed border-border-subtle rounded-lg bg-surface-elevated">
            <Upload className="h-10 w-10 text-muted mb-4" />
            <p className="text-sm text-primary mb-2">Upload a PCAP or PCAPNG capture to begin analysis.</p>
            <p className="text-xs text-muted mb-6">Select a valid network capture file.</p>
            
            <input 
              type="file" 
              ref={fileInputRef}
              onChange={handleFileSelect}
              className="hidden"
              accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/x-pcapng"
              aria-label="Select PCAP file"
            />
            
            {!selectedFile ? (
              <Button onClick={() => fileInputRef.current?.click()} variant="secondary">
                Select File
              </Button>
            ) : (
              <div className="w-full max-w-md">
                <div className="flex items-center justify-between bg-background p-3 rounded border border-border-subtle mb-4">
                  <div className="flex items-center gap-3 overflow-hidden">
                    <FileIcon className="h-5 w-5 text-accent flex-shrink-0" />
                    <div className="truncate">
                      <p className="text-sm font-medium text-primary truncate">{selectedFile.name}</p>
                      <p className="text-xs text-muted">{(selectedFile.size / (1024 * 1024)).toFixed(2)} MB</p>
                    </div>
                  </div>
                  <Button 
                    variant="secondary" 
                    size="sm" 
                    onClick={handleUpload}
                    disabled={isUploading}
                  >
                    {isUploading ? <><Spinner size={14} className="mr-2" /> Uploading...</> : 'Upload'}
                  </Button>
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
        </CardContent>
      </Card>
    );
  }

  // Render Metadata UI if acquisition exists
  return (
    <Card>
      <CardHeader className="pb-3 border-b border-border-subtle mb-4">
        <CardTitle className="text-base flex items-center gap-2">
          <FileIcon className="h-5 w-5 text-accent" aria-hidden="true" />
          Evidence Acquisition
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="space-y-4">
            <div>
              <p className="text-xs text-muted mb-1">File Name</p>
              <p className="text-sm font-medium text-primary">{acquisition.file_name}</p>
            </div>
            <div>
              <p className="text-xs text-muted mb-1">Size & Format</p>
              <p className="text-sm text-secondary">
                {(acquisition.file_size / (1024 * 1024)).toFixed(2)} MB • <span className="uppercase">{acquisition.format}</span>
              </p>
            </div>
            <div>
              <p className="text-xs text-muted mb-1">Uploaded At</p>
              <p className="text-sm text-secondary">{new Date(acquisition.ingested_at).toLocaleString()}</p>
            </div>
            <div>
              <p className="text-xs text-muted mb-1">Upload Status</p>
              <Badge variant={acquisition.status === 'complete' ? 'success' : acquisition.status === 'failed' ? 'danger' : 'info'}>
                {acquisition.status}
              </Badge>
            </div>
          </div>
          
          <div className="space-y-4 bg-surface-elevated p-4 rounded border border-border-subtle">
            <div className="flex items-center gap-2 mb-2">
              <Shield className="h-4 w-4 text-secondary" />
              <h3 className="text-sm font-medium text-primary">Cryptographic Integrity</h3>
            </div>
            
            {evidence ? (
              <>
                <div className="mb-4">
                  <p className="text-xs text-muted mb-1">SHA-256 Hash</p>
                  <p className="text-xs font-mono text-secondary break-all bg-background p-2 rounded border border-border-subtle">
                    {evidence.sha256_hash || 'Pending computation...'}
                  </p>
                </div>
                <div className="flex items-center justify-between">
                  <EvidenceVerificationBadge status={evidence.status} />
                  
                  {evidence.sha256_hash && (
                    <Button 
                      variant="secondary" 
                      size="sm" 
                      onClick={handleVerify}
                      disabled={isVerifying}
                    >
                      {isVerifying ? <><Spinner size={14} className="mr-2" /> Verifying</> : 'Verify Integrity'}
                    </Button>
                  )}
                </div>
              </>
            ) : (
              <p className="text-sm text-muted">Evidence record is being generated...</p>
            )}

            {errorMsg && (
              <div className="flex items-start gap-2 text-sm text-danger mt-3 bg-danger/10 p-2 rounded">
                <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <p>{errorMsg}</p>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
