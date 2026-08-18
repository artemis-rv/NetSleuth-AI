import { useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { ChevronLeft, Edit2, X, Calendar, Clock, User, Zap, Target } from 'lucide-react';
import { useCaseQuery } from '../hooks';
import { EditCaseForm } from '../components/EditCaseForm';
import { CaseStatusBadge, CasePriorityBadge } from '../components/CaseBadge';
import { Button } from '../../../components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../../../components/ui/Card';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import { ErrorState } from '../../../components/feedback/ErrorState';
import { ApiError } from '../../../api/errors';
import type { CaseResponse } from '../types';

function formatDateTime(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
  });
}

function MetaItem({ icon: Icon, label, value }: { icon: any; label: string; value: string | null | undefined }) {
  if (!value) return null;
  return (
    <div className="flex items-start gap-2.5">
      <Icon className="h-4 w-4 text-muted mt-0.5 flex-shrink-0" aria-hidden="true" />
      <div>
        <p className="text-xs text-muted mb-0.5">{label}</p>
        <p className="text-sm text-primary">{value}</p>
      </div>
    </div>
  );
}

// Tab definitions — only Overview is functional in FE-1
const TABS = [
  { id: 'overview', label: 'Overview', active: true },
  { id: 'findings', label: 'Findings', active: false },
  { id: 'network', label: 'Network', active: false },
  { id: 'timeline', label: 'Timeline', active: false },
  { id: 'graph', label: 'Graph', active: false },
  { id: 'mitre', label: 'MITRE', active: false },
  { id: 'evidence', label: 'Evidence', active: false },
  { id: 'reports', label: 'Reports', active: false },
] as const;

function CaseOverview({ caseData }: { caseData: CaseResponse }) {
  return (
    <div className="space-y-6">
      {/* Trigger Panel */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Zap className="h-4 w-4 text-warning" aria-hidden="true" />
            Triggering Event
          </CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <div className="space-y-3">
            <div>
              <p className="text-xs text-muted mb-1">Trigger Type</p>
              <span className="inline-flex items-center rounded border border-border-subtle bg-surface-elevated px-2.5 py-1 text-xs font-medium text-secondary">
                {caseData.trigger_type.replace(/_/g, ' ')}
              </span>
            </div>
            {caseData.trigger_description && (
              <div>
                <p className="text-xs text-muted mb-1">Description</p>
                <p className="text-sm text-primary whitespace-pre-wrap leading-relaxed">
                  {caseData.trigger_description}
                </p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Investigation Goals Panel */}
      {caseData.investigation_goals && caseData.investigation_goals.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Target className="h-4 w-4 text-accent" aria-hidden="true" />
              Investigation Goals
            </CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <ol className="space-y-2" aria-label="Investigation goals">
              {caseData.investigation_goals.map((goal, idx) => (
                <li key={idx} className="flex items-start gap-2.5 text-sm text-primary">
                  <span className="flex-shrink-0 h-5 w-5 rounded-full bg-surface-elevated border border-border-subtle flex items-center justify-center text-xs text-muted font-medium">
                    {idx + 1}
                  </span>
                  <span className="leading-relaxed">{goal}</span>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      )}

      {/* Metadata Panel */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm">Case Metadata</CardTitle>
        </CardHeader>
        <CardContent className="pt-0">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <MetaItem icon={Calendar} label="Opened" value={formatDateTime(caseData.opened_at)} />
            <MetaItem icon={Clock} label="Last Updated" value={formatDateTime(caseData.updated_at)} />
            {caseData.closed_at && (
              <MetaItem icon={Calendar} label="Closed" value={formatDateTime(caseData.closed_at)} />
            )}
            <MetaItem icon={User} label="Reported By" value={caseData.reported_by} />
            <MetaItem icon={User} label="External Case ID" value={caseData.external_case_id} />
            <MetaItem icon={User} label="External System" value={caseData.external_system} />
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

export function CaseDetailPage() {
  const { caseId } = useParams<{ caseId: string }>();
  const [activeTab, setActiveTab] = useState<string>('overview');
  const [editing, setEditing] = useState(false);

  const { data: caseData, isLoading, isError, error, refetch } = useCaseQuery(caseId ?? '');

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <Spinner size={32} />
      </div>
    );
  }

  if (isError) {
    const apiErr = error as ApiError;
    if (apiErr?.status === 403) {
      return (
        <EmptyState
          title="Access Denied"
          description="You do not have permission to view this investigation."
          action={
            <Link to="/investigations">
              <Button variant="secondary">Back to Investigations</Button>
            </Link>
          }
        />
      );
    }
    if (apiErr?.status === 404) {
      return (
        <EmptyState
          title="Investigation Not Found"
          description="This investigation does not exist or has been removed."
          action={
            <Link to="/investigations">
              <Button variant="secondary">Back to Investigations</Button>
            </Link>
          }
        />
      );
    }
    return <ErrorState error={error as Error} retry={() => refetch()} />;
  }

  if (!caseData) return null;

  return (
    <div>
      {/* Breadcrumb */}
      <div className="mb-4">
        <Link
          to="/investigations"
          className="inline-flex items-center text-sm text-muted hover:text-primary transition-colors"
        >
          <ChevronLeft className="h-4 w-4 mr-1" aria-hidden="true" />
          Investigations
        </Link>
      </div>

      {/* Case Header */}
      <div className="flex items-start justify-between mb-6 gap-4">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 mb-2 flex-wrap">
            <CaseStatusBadge status={caseData.status} />
            <CasePriorityBadge priority={caseData.priority} />
          </div>
          <h1 className="text-xl font-bold tracking-tight text-primary leading-tight">
            {caseData.title}
          </h1>
          {caseData.description && (
            <p className="text-sm text-secondary mt-2 leading-relaxed">{caseData.description}</p>
          )}
          <p className="text-xs text-muted mt-2 font-mono">ID: {caseData.case_id}</p>
        </div>
        <div className="flex-shrink-0 flex gap-2">
          <Button
            variant="secondary"
            size="sm"
            onClick={() => setEditing((prev) => !prev)}
            aria-label={editing ? 'Cancel editing' : 'Edit case'}
          >
            {editing ? (
              <><X className="h-4 w-4 mr-1" aria-hidden="true" /> Cancel</>
            ) : (
              <><Edit2 className="h-4 w-4 mr-1" aria-hidden="true" /> Edit</>
            )}
          </Button>
        </div>
      </div>

      {/* Edit Form */}
      {editing && (
        <Card className="mb-6">
          <CardHeader>
            <CardTitle className="text-base">Edit Investigation</CardTitle>
          </CardHeader>
          <CardContent>
            <EditCaseForm
              caseData={caseData}
              onSuccess={() => { setEditing(false); refetch(); }}
              onCancel={() => setEditing(false)}
            />
          </CardContent>
        </Card>
      )}

      {/* Tabs */}
      {!editing && (
        <>
          <div
            className="flex border-b border-border-subtle mb-6 overflow-x-auto"
            role="tablist"
            aria-label="Case sections"
          >
            {TABS.map((tab) => (
              <button
                key={tab.id}
                role="tab"
                id={`tab-${tab.id}`}
                aria-selected={activeTab === tab.id}
                aria-controls={`panel-${tab.id}`}
                onClick={() => tab.active && setActiveTab(tab.id)}
                disabled={!tab.active}
                className={`px-4 py-2.5 text-sm font-medium whitespace-nowrap border-b-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                  activeTab === tab.id
                    ? 'border-accent text-accent'
                    : tab.active
                    ? 'border-transparent text-secondary hover:text-primary hover:border-border-subtle'
                    : 'border-transparent text-muted cursor-not-allowed opacity-50'
                }`}
                title={!tab.active ? 'Available in a future phase' : undefined}
              >
                {tab.label}
                {!tab.active && (
                  <span className="ml-1.5 text-xs text-muted font-normal hidden sm:inline">(soon)</span>
                )}
              </button>
            ))}
          </div>

          <div
            role="tabpanel"
            id={`panel-${activeTab}`}
            aria-labelledby={`tab-${activeTab}`}
          >
            {activeTab === 'overview' && <CaseOverview caseData={caseData} />}
          </div>
        </>
      )}
    </div>
  );
}
