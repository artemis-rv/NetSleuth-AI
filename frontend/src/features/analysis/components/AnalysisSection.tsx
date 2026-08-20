import { Play, CheckCircle2, AlertCircle, Activity, ArrowRight } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../../components/ui/Card';
import { Button } from '../../../components/ui/Button';
import { Badge } from '../../../components/ui/Badge';
import { Spinner } from '../../../components/ui/Spinner';
import { useAnalysisJobs, useStartAnalysis } from '../hooks';
import type { AnalysisJobResponse } from '../types';
import { ApiError } from '../../../api/errors';
import { useState } from 'react';

import type { AcquisitionResponse } from '../../acquisition/types';

interface AnalysisSectionProps {
  caseId: string;
  acquisitionId?: string | undefined;
  acquisitions?: AcquisitionResponse[];
  onViewFindings?: () => void;
}

const STAGES = ['QUEUED', 'M1', 'M2', 'M3', 'M4', 'COMPLETED'];

export function AnalysisSection({ caseId, acquisitionId, acquisitions = [], onViewFindings }: AnalysisSectionProps) {
  const { data, isLoading } = useAnalysisJobs(caseId);
  const startMutation = useStartAnalysis(caseId);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const jobs = data?.jobs || [];
  const sortedJobs = [...jobs].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  const activeJob = sortedJobs.find(j => j.status === 'queued' || j.status === 'running');
  const latestJob = sortedJobs[0];

  const handleStartAnalysis = async () => {
    setErrorMsg(null);
    const targetAcquisitionIds: string[] = [];
    
    if (acquisitions && acquisitions.length > 0) {
      targetAcquisitionIds.push(...acquisitions.map(a => a.acquisition_id));
    } else if (acquisitionId) {
      targetAcquisitionIds.push(acquisitionId);
    }

    if (targetAcquisitionIds.length === 0) return;

    // Trigger analysis for target acquisitions
    for (const acqId of targetAcquisitionIds) {
      try {
        await startMutation.mutateAsync(acqId);
      } catch (error) {
        const msg = error instanceof ApiError ? error.message : 'Failed to start analysis for some files.';
        setErrorMsg(msg);
      }
    }
  };

  const renderStageTimeline = (job: AnalysisJobResponse) => {
    if (job.status === 'failed') {
      return (
        <div className="flex items-center gap-2 text-danger mt-4 bg-danger/10 p-3 rounded border border-danger/20">
          <AlertCircle className="h-5 w-5 flex-shrink-0" />
          <div>
            <p className="text-sm font-medium">Analysis Failed at {job.current_stage}</p>
            {job.error_code && <p className="text-xs opacity-90 font-mono mt-1">{job.error_code}</p>}
          </div>
        </div>
      );
    }

    const currentStageIndex = STAGES.indexOf(job.current_stage);
    
    return (
      <div className="mt-6">
        <div className="flex items-center justify-between mb-2">
          <p className="text-sm font-medium text-primary">Processing Pipeline</p>
          {job.progress !== null && (
            <p className="text-xs font-medium text-accent">{job.progress}%</p>
          )}
        </div>
        
        <div className="relative">
          {/* Track line */}
          <div className="absolute top-1/2 left-0 w-full h-0.5 bg-border-subtle -translate-y-1/2 rounded" />
          
          <div className="relative flex justify-between px-2">
            {STAGES.map((stage, idx) => {
              const isPast = currentStageIndex > idx || job.status === 'completed';
              const isCurrent = currentStageIndex === idx && job.status !== 'completed';
              return (
                <div key={stage} className="flex flex-col items-center group relative z-10 w-8">
                  <div 
                    className={`w-5 h-5 rounded-full flex items-center justify-center border transition-all duration-300 ${
                      isPast 
                        ? 'bg-success/20 border-success text-success shadow-[0_0_10px_rgba(16,185,129,0.3)]' 
                        : isCurrent 
                        ? 'bg-accent/20 border-accent text-accent shadow-[0_0_12px_rgba(59,130,246,0.5)]' 
                        : 'bg-surface border-border-subtle text-transparent'
                    }`}
                  >
                    {isPast ? <CheckCircle2 className="h-3 w-3" /> : isCurrent ? <div className="w-1.5 h-1.5 rounded-full bg-accent animate-pulse" /> : null}
                  </div>
                  <p className={`mt-2 text-[10px] font-bold tracking-widest absolute top-5 whitespace-nowrap ${
                    isPast ? 'text-success' : isCurrent ? 'text-accent' : 'text-muted'
                  }`}>
                    {stage}
                  </p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    );
  };

  return (
    <Card className="flex flex-col h-full border-border-subtle bg-surface-elevated/30">
      <CardHeader className="pb-2 border-b border-border-subtle/50 px-5 pt-5 mb-4">
        <CardTitle className="text-sm flex items-center gap-2">
          <Activity className="h-4 w-4 text-accent" aria-hidden="true" />
          Analysis Jobs
        </CardTitle>
      </CardHeader>
      <CardContent className="px-5 py-4 flex-1">
        {!acquisitionId && acquisitions.length === 0 ? (
          <div className="text-center py-6 text-muted text-sm">
            Please upload an acquisition first before starting analysis.
          </div>
        ) : (
          <div className="space-y-6">
            <div className="flex items-start justify-between">
              <div>
                <p className="text-[11px] uppercase tracking-wider text-muted font-semibold mb-1">Automated Pipeline</p>
                <p className="text-[13px] text-secondary">Runs packet intelligence, parsing, correlation, and evidence generation.</p>
              </div>
              
              {!activeJob && (
                <Button 
                  onClick={handleStartAnalysis} 
                  disabled={startMutation.isPending}
                  size="sm"
                  className="h-8 text-xs shrink-0"
                >
                  {startMutation.isPending ? (
                    <><Spinner size={14} className="mr-2" /> Starting...</>
                  ) : (
                    <><Play className="h-3 w-3 mr-1.5" /> Start Analysis</>
                  )}
                </Button>
              )}
            </div>

            {errorMsg && (
              <div className="flex items-start gap-2 text-sm text-danger bg-danger/10 p-2 rounded">
                <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <p>{errorMsg}</p>
              </div>
            )}

            {isLoading && (
              <div className="flex justify-center py-4">
                <Spinner size={24} />
              </div>
            )}

            {latestJob && !isLoading && (
              <div className="bg-surface p-5 rounded-lg border border-border-subtle mt-6">
                <div className="flex items-start justify-between mb-4">
                  <div>
                    <h3 className="text-[13px] font-medium text-primary flex items-center gap-2">
                      <span className="font-mono text-accent">#{latestJob.analysis_id.split('-')[0]}</span>
                      <span>Current Job</span>
                    </h3>
                    <p className="text-[11px] text-muted mt-1">
                      Started: {new Date(latestJob.started_at).toLocaleString()}
                    </p>
                  </div>
                  <Badge 
                    variant={
                      latestJob.status === 'completed' ? 'success' :
                      latestJob.status === 'failed' ? 'danger' :
                      latestJob.status === 'cancelled' ? 'warning' : 'info'
                    }
                    className="h-5 px-2 text-[10px]"
                  >
                    {latestJob.status.toUpperCase()}
                  </Badge>
                </div>
                
                {renderStageTimeline(latestJob)}
                
                {latestJob.status === 'completed' && (
                  <div className="mt-10 flex justify-end">
                    <Button variant="secondary" className="gap-1.5" onClick={onViewFindings}>
                      View Findings <ArrowRight className="h-4 w-4" />
                    </Button>
                  </div>
                )}
              </div>
            )}
            
            {sortedJobs.length > 1 && (
              <div className="mt-8">
                <p className="text-[11px] uppercase tracking-wider text-muted font-semibold mb-3">Previous Runs</p>
                <div className="rounded-md border border-border-subtle bg-surface/30 overflow-hidden">
                  <div className="grid grid-cols-[80px_1fr_auto] sm:grid-cols-[100px_1fr_100px_auto] items-center gap-4 bg-surface-elevated/50 p-2.5 border-b border-border-subtle text-[11px] font-medium text-muted uppercase tracking-wider">
                    <div>Run</div>
                    <div>Started</div>
                    <div className="hidden sm:block">Status</div>
                    <div className="text-right">Action</div>
                  </div>
                  <div className="divide-y divide-border-subtle">
                    {sortedJobs.slice(1, 4).map(job => (
                      <div key={job.analysis_id} className="grid grid-cols-[80px_1fr_auto] sm:grid-cols-[100px_1fr_100px_auto] items-center gap-4 p-2.5 text-[13px] hover:bg-surface/80 transition-colors">
                        <span className="text-primary font-mono text-[11px]">{job.analysis_id.split('-')[0]}</span>
                        <span className="text-secondary text-[12px]">{new Date(job.started_at).toLocaleString()}</span>
                        <div className="hidden sm:block">
                          <Badge 
                            variant={job.status === 'completed' ? 'success' : job.status === 'failed' ? 'danger' : 'default'}
                            className="text-[10px] h-4 px-1.5"
                          >
                            {job.status}
                          </Badge>
                        </div>
                        <div className="text-right flex items-center justify-end gap-2">
                          {/* Show badge on mobile where column is hidden */}
                          <div className="sm:hidden">
                            <Badge 
                              variant={job.status === 'completed' ? 'success' : job.status === 'failed' ? 'danger' : 'default'}
                              className="text-[10px] h-4 px-1.5"
                            >
                              {job.status}
                            </Badge>
                          </div>
                          {job.status === 'completed' && (
                            <Button variant="secondary" size="sm" onClick={onViewFindings} className="h-6 text-[11px] px-3 font-semibold tracking-wider hover:bg-surface-elevated transition-colors border border-border-subtle/50 shadow-sm hover:shadow-md">
                              View
                            </Button>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
