import { Play, CheckCircle2, AlertCircle, Activity, ArrowRight } from 'lucide-react';
import { Card, CardContent, CardHeader, CardTitle } from '../../../components/ui/Card';
import { Button } from '../../../components/ui/Button';
import { Badge } from '../../../components/ui/Badge';
import { Spinner } from '../../../components/ui/Spinner';
import { useAnalysisJobs, useStartAnalysis } from '../hooks';
import type { AnalysisJobResponse } from '../types';
import { ApiError } from '../../../api/errors';
import { useState } from 'react';

interface AnalysisSectionProps {
  caseId: string;
  acquisitionId: string | undefined;
}

const STAGES = ['QUEUED', 'M1', 'M2', 'M3', 'M4', 'COMPLETED'];

export function AnalysisSection({ caseId, acquisitionId }: AnalysisSectionProps) {
  const { data, isLoading } = useAnalysisJobs(caseId);
  const startMutation = useStartAnalysis(caseId);
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  const jobs = data?.jobs || [];
  // Sort jobs by started_at descending
  const sortedJobs = [...jobs].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime());
  const activeJob = sortedJobs.find(j => j.status === 'queued' || j.status === 'running');
  const latestJob = sortedJobs[0];

  const handleStartAnalysis = () => {
    if (!acquisitionId) return;
    setErrorMsg(null);
    startMutation.mutate(acquisitionId, {
      onError: (error) => {
        const msg = error instanceof ApiError ? error.message : 'Failed to start analysis.';
        setErrorMsg(msg);
      }
    });
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
          
          <div className="relative flex justify-between">
            {STAGES.map((stage, idx) => {
              const isPast = currentStageIndex > idx || job.status === 'completed';
              const isCurrent = currentStageIndex === idx && job.status !== 'completed';
              return (
                <div key={stage} className="flex flex-col items-center group relative">
                  <div 
                    className={`w-6 h-6 rounded-full flex items-center justify-center border-2 z-10 transition-colors ${
                      isPast 
                        ? 'bg-success border-success text-white' 
                        : isCurrent 
                        ? 'bg-background border-accent text-accent animate-pulse' 
                        : 'bg-surface-elevated border-border-subtle text-muted'
                    }`}
                  >
                    {isPast ? <CheckCircle2 className="h-4 w-4" /> : <div className="w-2 h-2 rounded-full bg-current" />}
                  </div>
                  <p className={`mt-2 text-xs font-medium absolute top-6 whitespace-nowrap ${
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
    <Card>
      <CardHeader className="pb-3 border-b border-border-subtle mb-4">
        <CardTitle className="text-base flex items-center gap-2">
          <Activity className="h-5 w-5 text-accent" aria-hidden="true" />
          Analysis Jobs
        </CardTitle>
      </CardHeader>
      <CardContent>
        {!acquisitionId ? (
          <div className="text-center py-6 text-muted text-sm">
            Please upload an acquisition first before starting analysis.
          </div>
        ) : (
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium text-primary mb-1">Automated Pipeline</p>
                <p className="text-xs text-muted">Runs packet intelligence, parsing, correlation, and evidence generation.</p>
              </div>
              
              {!activeJob && (
                <Button 
                  onClick={handleStartAnalysis} 
                  disabled={startMutation.isPending}
                >
                  {startMutation.isPending ? (
                    <><Spinner size={16} className="mr-2" /> Starting...</>
                  ) : (
                    <><Play className="h-4 w-4 mr-1.5" /> Start Analysis</>
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
              <div className="bg-surface p-4 rounded-lg border border-border-subtle mt-4">
                <div className="flex items-start justify-between mb-2">
                  <div>
                    <h3 className="text-sm font-medium text-primary">Job {latestJob.analysis_id.split('-')[0]}</h3>
                    <p className="text-xs text-muted">
                      Started: {new Date(latestJob.started_at).toLocaleString()}
                    </p>
                  </div>
                  <Badge 
                    variant={
                      latestJob.status === 'completed' ? 'success' :
                      latestJob.status === 'failed' ? 'danger' :
                      latestJob.status === 'cancelled' ? 'warning' : 'info'
                    }
                  >
                    {latestJob.status.toUpperCase()}
                  </Badge>
                </div>
                
                {renderStageTimeline(latestJob)}
                
                {latestJob.status === 'completed' && (
                  <div className="mt-10 flex justify-end">
                    <Button variant="secondary" className="gap-1.5" disabled title="Findings available in next module">
                      View Findings <ArrowRight className="h-4 w-4" />
                    </Button>
                  </div>
                )}
              </div>
            )}
            
            {sortedJobs.length > 1 && (
              <div className="mt-4 pt-4 border-t border-border-subtle">
                <p className="text-xs text-muted font-medium mb-3">Previous Runs</p>
                <div className="space-y-2">
                  {sortedJobs.slice(1, 4).map(job => (
                    <div key={job.analysis_id} className="flex items-center justify-between p-2 text-sm rounded hover:bg-surface-elevated">
                      <span className="text-secondary font-mono text-xs">{job.analysis_id.split('-')[0]}</span>
                      <span className="text-muted text-xs">{new Date(job.started_at).toLocaleString()}</span>
                      <Badge 
                        variant={job.status === 'completed' ? 'success' : job.status === 'failed' ? 'danger' : 'default'}
                      >
                        {job.status}
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
