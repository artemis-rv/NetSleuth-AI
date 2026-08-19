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

const STAGES = [
  'QUEUED',
  'M1_PACKET_INTELLIGENCE',
  'M2_ANALYSIS',
  'M3_CORRELATION',
  'M4_REPORTING',
  'COMPLETED'
];

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

  const getStageIndex = (stage: string | null | undefined): number => {
    if (!stage) return -1;
    switch (stage) {
      case 'INITIALIZING':
      case 'LOADING_ACQUISITION':
        return 0; // QUEUED
      case 'M1_PACKET_INTELLIGENCE':
        return 1; // M1
      case 'M2_ANALYSIS':
        return 2; // M2
      case 'M3_CORRELATION':
        return 3; // M3
      case 'M4_REPORTING':
        return 4; // M4
      case 'COMPLETED':
        return 5; // COMPLETED
      default:
        return -1;
    }
  };

  const renderStageTimeline = (job: AnalysisJobResponse) => {
    if (job.status === 'failed') {
      return (
        <div className="flex items-center gap-3 text-danger mt-6 bg-danger/10 p-4 rounded-lg border border-danger/20">
          <AlertCircle className="h-6 w-6 flex-shrink-0" />
          <div>
            <p className="text-sm font-semibold">Analysis Failed at {job.current_stage}</p>
            {job.error_code && <p className="text-xs opacity-90 font-mono mt-1">{job.error_code}</p>}
          </div>
        </div>
      );
    }

    const currentStageIndex = getStageIndex(job.current_stage);
    
    return (
      <div className="mt-6 mb-2">
        <div className="flex items-center justify-between mb-5">
          <p className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-2">
            <Activity className="h-3.5 w-3.5 text-accent" />
            Processing Pipeline
          </p>
          {job.progress !== null && (
            <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded border ${
              job.status === 'completed' 
                ? 'bg-success/10 text-success border-success/30' 
                : 'bg-accent/10 text-accent border-accent/30'
            }`}>
              {job.progress}%
            </span>
          )}
        </div>
        
        <div className="relative px-3 pt-2 pb-6">
          {/* Continuous track line (background) */}
          <div className="absolute top-5 left-6 right-6 h-1 bg-surface-elevated rounded-full z-0" />
          
          {/* Active track line (progress) */}
          <div 
            className={`absolute top-5 left-6 h-1 rounded-full z-0 transition-all duration-500 ease-in-out ${job.status === 'completed' ? 'bg-success' : 'bg-accent'}`}
            style={{ width: `calc(${Math.min(100, Math.max(0, job.status === 'completed' ? 100 : (currentStageIndex / (STAGES.length - 1)) * 100))}% - 3rem)` }}
          />
          
          <div className="relative flex justify-between z-10">
            {STAGES.map((stage, idx) => {
              const isPast = currentStageIndex > idx || job.status === 'completed';
              const isCurrent = currentStageIndex === idx && job.status !== 'completed';
              return (
                <div key={stage} className="flex flex-col items-center group relative">
                  <div 
                    className={`w-7 h-7 rounded-full flex items-center justify-center border-[2.5px] transition-all duration-300 ${
                      isPast 
                        ? 'bg-success border-success text-white shadow-sm' 
                        : isCurrent 
                        ? 'bg-background border-accent text-accent ring-4 ring-accent/20 scale-110' 
                        : 'bg-surface-elevated border-border-subtle text-transparent'
                    }`}
                  >
                    {isPast ? <CheckCircle2 className="h-4 w-4" strokeWidth={3} /> : <div className={`w-2 h-2 rounded-full ${isCurrent ? 'bg-accent' : 'bg-transparent'}`} />}
                  </div>
                  <p className={`mt-3 text-[10px] font-bold tracking-wider absolute top-7 whitespace-nowrap uppercase ${
                    isPast ? 'text-primary' : isCurrent ? 'text-accent' : 'text-muted'
                  }`}>
                    {stage.replace('M1_PACKET_INTELLIGENCE', 'M1').replace('M2_ANALYSIS', 'M2').replace('M3_CORRELATION', 'M3').replace('M4_REPORTING', 'M4')}
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
    <Card className="border-border-subtle shadow-sm mb-6">
      <CardHeader className="p-6 pb-4 border-b border-border-subtle flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <CardTitle className="text-base font-semibold flex items-center gap-2 mb-1">
            <Activity className="h-4 w-4 text-accent" aria-hidden="true" />
            Analysis Jobs
          </CardTitle>
          <p className="text-xs text-muted">Runs packet intelligence, parsing, correlation, and evidence generation.</p>
        </div>
        
        {/* Start Analysis Button in Header */}
        {!activeJob && acquisitionId && (
          <Button 
            onClick={handleStartAnalysis} 
            disabled={startMutation.isPending}
            className="flex-shrink-0 shadow-sm hover:shadow bg-accent text-white hover:bg-accent/90"
          >
            {startMutation.isPending ? (
              <><Spinner size={16} className="mr-2" /> Starting...</>
            ) : (
              <><Play className="h-4 w-4 mr-1.5" /> Start Analysis</>
            )}
          </Button>
        )}
      </CardHeader>
      
      <CardContent className="p-6">
        {!acquisitionId ? (
          <div className="text-center py-10 bg-surface-elevated/30 rounded-xl border border-dashed border-border-subtle text-muted text-sm">
            Please upload an acquisition first before starting analysis.
          </div>
        ) : (
          <div className="space-y-6">
            {errorMsg && (
              <div className="flex items-start gap-2 text-sm text-danger bg-danger/10 p-3 rounded-lg border border-danger/20">
                <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
                <p>{errorMsg}</p>
              </div>
            )}

            {isLoading && (
              <div className="flex justify-center py-10">
                <Spinner size={28} />
              </div>
            )}

            {!latestJob && !isLoading && acquisitionId && (
              <div className="text-center py-12 px-6 bg-surface-elevated/20 rounded-xl border border-dashed border-border-subtle">
                <div className="mx-auto w-12 h-12 rounded-full bg-accent/10 flex items-center justify-center text-accent mb-4 border border-accent/20">
                  <Play className="h-6 w-6 ml-0.5" />
                </div>
                <h4 className="text-base font-semibold text-primary mb-2">Analysis Has Not Been Started</h4>
                <p className="text-sm text-muted max-w-md mx-auto mb-6 leading-relaxed">
                  An acquisition file is linked to this case. Click Start Analysis to execute packet intelligence, network flow parsing, threat correlation, and report generation.
                </p>
                <Button onClick={handleStartAnalysis} disabled={startMutation.isPending} className="shadow-sm bg-accent text-white hover:bg-accent/90">
                  {startMutation.isPending ? (
                    <><Spinner size={16} className="mr-2" /> Starting...</>
                  ) : (
                    <><Play className="h-4 w-4 mr-2" /> Start Analysis</>
                  )}
                </Button>
              </div>
            )}

            {latestJob && !isLoading && (
              <div className="bg-surface p-6 rounded-xl border border-border-subtle/80 shadow-sm relative overflow-hidden space-y-6">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-4 border-b border-border-subtle/50">
                  <div>
                    <h3 className="text-sm font-semibold text-primary flex items-center gap-2">
                      Current Analysis 
                      <span className="text-xs font-mono text-muted bg-surface-elevated px-2 py-0.5 rounded border border-border-subtle">
                        {latestJob.analysis_id.split('-')[0]}
                      </span>
                    </h3>
                    <p className="text-xs text-muted mt-1 flex items-center gap-1.5">
                      <span className="inline-block w-1.5 h-1.5 rounded-full bg-accent"></span>
                      Started {new Date(latestJob.started_at).toLocaleString()}
                    </p>
                  </div>
                  <Badge 
                    variant={
                      latestJob.status === 'completed' ? 'success' :
                      latestJob.status === 'failed' ? 'danger' :
                      latestJob.status === 'cancelled' ? 'warning' : 'info'
                    }
                    className="px-3 py-1 text-[11px] font-bold tracking-wider uppercase self-start sm:self-auto"
                  >
                    {latestJob.status.toUpperCase()}
                  </Badge>
                </div>
                
                {renderStageTimeline(latestJob)}
                
                {latestJob.status === 'completed' && (latestJob.findings_count ?? 0) > 0 && (
                  <div className="pt-4 border-t border-border-subtle/50 flex justify-end">
                    <Button variant="secondary" className="gap-2 text-xs shadow-sm border-border-subtle hover:border-primary/30 hover:bg-surface-elevated transition-all" onClick={onViewFindings}>
                      View Findings <ArrowRight className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                )}
              </div>
            )}
            
            {sortedJobs.length > 1 && (
              <div className="mt-8 pt-6 border-t border-border-subtle">
                <h4 className="text-xs uppercase tracking-wider text-muted font-semibold mb-4 flex items-center gap-2">
                  <Activity className="h-3.5 w-3.5 text-muted" />
                  Previous Runs
                </h4>
                <div className="space-y-3">
                  {sortedJobs.slice(1, 4).map(job => (
                    <div key={job.analysis_id} className="flex flex-col sm:flex-row sm:items-center justify-between p-3.5 bg-surface rounded-lg border border-border-subtle hover:border-accent/30 transition-colors gap-2">
                      <div className="flex items-center gap-3">
                        <Activity className="h-4 w-4 text-muted" />
                        <div>
                          <p className="text-xs text-primary font-medium">Job <span className="font-mono text-xs text-secondary">{job.analysis_id.split('-')[0]}</span></p>
                          <p className="text-[11px] text-muted">{new Date(job.started_at).toLocaleString()}</p>
                        </div>
                      </div>
                      <Badge 
                        variant={job.status === 'completed' ? 'success' : job.status === 'failed' ? 'danger' : 'default'}
                        className="self-start sm:self-auto text-[10px] uppercase font-bold"
                      >
                        {job.status.toUpperCase()}
                      </Badge>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
