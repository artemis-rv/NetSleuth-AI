import { useState, useMemo } from 'react';
import { useParams, Link, useSearchParams } from 'react-router-dom';
import { ChevronLeft, Edit2, X, Calendar, Clock, User, Zap, Target, CheckSquare, Square, Plus, Save } from 'lucide-react';
import { useCaseQuery, useUpdateCaseMutation } from '../hooks';
import { EditCaseForm } from '../components/EditCaseForm';
import { CaseStatusBadge, CasePriorityBadge } from '../components/CaseBadge';
import { Button } from '../../../components/ui/Button';
import { Card, CardContent, CardHeader, CardTitle } from '../../../components/ui/Card';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import { ErrorState } from '../../../components/feedback/ErrorState';
import { ApiError } from '../../../api/errors';
import type { CaseResponse, InvestigationGoal } from '../types';

// FE-2
import { AcquisitionSection } from '../../acquisition/components/AcquisitionSection';
import { AnalysisSection } from '../../analysis/components/AnalysisSection';
import { useAcquisitions, useEvidence } from '../../acquisition/hooks';

// FE-3
import { FindingsSection } from '../../findings/components/FindingsSection';
import { NetworkSection } from '../../network/components/NetworkSection';

// FE-4/5
import { TimelineSection } from '../../investigation/components/TimelineSection';
import { EntitiesSection } from '../../investigation/components/EntitiesSection';
import { RelationshipsSection } from '../../investigation/components/RelationshipsSection';
import { BehaviorsSection } from '../../investigation/components/BehaviorsSection';
import { MitreSection } from '../../investigation/components/MitreSection';
import { GraphSection } from '../../investigation/components/GraphSection';
import { AttackChainSection } from '../../investigation/components/AttackChainSection';

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

// FE-6
import { EvidenceSection } from '../../evidence/components/EvidenceSection';
import { ReportsSection } from '../../reports/components/ReportsSection';

// FE-7
import { CopilotPanel } from '../../copilot/components/CopilotPanel';

// ─── Top-level tab definitions ───────────────────────────────────────────────
const TABS = [
  { id: 'overview', label: 'Overview' },
  { id: 'findings', label: 'Findings' },
  { id: 'network', label: 'Network' },
  { id: 'timeline', label: 'Timeline' },
  { id: 'graph', label: 'Graph' },
  { id: 'mitre', label: 'MITRE' },
  { id: 'evidence', label: 'Evidence' },
  { id: 'reports', label: 'Reports' },
  { id: 'copilot', label: 'AI Copilot' },
] as const;

type TabId = (typeof TABS)[number]['id'];

// ─── Investigation sub-tabs (inside "timeline" slot) ─────────────────────────
const INVESTIGATION_SUBTABS = [
  { id: 'timeline', label: 'Timeline' },
  { id: 'entities', label: 'Entities' },
  { id: 'relationships', label: 'Relationships' },
  { id: 'behaviors', label: 'Behaviors' },
  { id: 'attack-chain', label: 'Attack Chain' },
] as const;

type InvestigationSubTabId = (typeof INVESTIGATION_SUBTABS)[number]['id'];



// ─── Investigation Goals Checklist ─────────────────────────────────────────────
function InvestigationGoalsChecklist({ caseData }: { caseData: CaseResponse }) {
  const updateCase = useUpdateCaseMutation(caseData.case_id);
  const [editingNoteId, setEditingNoteId] = useState<string | null>(null);
  const [draftNote, setDraftNote] = useState('');

  const goals: InvestigationGoal[] = useMemo(() => {
    if (!caseData?.investigation_goals) return [];
    return caseData.investigation_goals.map((g, idx) => {
      if (typeof g === 'string') {
        return { id: `goal-${idx}`, description: g, completed: false };
      }
      return g;
    });
  }, [caseData?.investigation_goals]);

  const toggleGoal = (goalId: string) => {
    const newGoals = goals.map(g => 
      g.id === goalId ? { ...g, completed: !g.completed } : g
    );
    updateCase.mutate({ investigation_goals: newGoals });
  };

  const saveNote = (goalId: string) => {
    const newGoals = goals.map(g => 
      g.id === goalId ? { ...g, note: draftNote.trim() || null } : g
    );
    updateCase.mutate({ investigation_goals: newGoals }, {
      onSuccess: () => setEditingNoteId(null)
    });
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2">
          <Target className="h-4 w-4 text-accent" aria-hidden="true" />
          Investigation Goals
        </CardTitle>
      </CardHeader>
      <CardContent className="pt-0">
        <div className="space-y-3" aria-label="Investigation goals">
          {goals.map((goal) => (
            <div key={goal.id} className="flex flex-col gap-2 p-3 rounded-lg border border-border-subtle bg-surface-elevated/50 transition-colors hover:bg-surface-elevated">
              <div className="flex items-start gap-3">
                <button
                  type="button"
                  onClick={() => toggleGoal(goal.id)}
                  className="mt-0.5 flex-shrink-0 text-muted hover:text-accent transition-colors"
                  aria-label={goal.completed ? "Mark incomplete" : "Mark complete"}
                >
                  {goal.completed ? (
                    <CheckSquare className="h-5 w-5 text-accent" />
                  ) : (
                    <Square className="h-5 w-5" />
                  )}
                </button>
                <div className="flex-1">
                  <span className={`text-sm leading-relaxed ${goal.completed ? 'text-muted line-through' : 'text-primary'}`}>
                    {goal.description}
                  </span>
                </div>
              </div>
              
              <div className="pl-8 flex flex-col gap-2">
                {editingNoteId === goal.id ? (
                  <div className="flex gap-2 items-start mt-1">
                    <textarea
                      value={draftNote}
                      onChange={(e) => setDraftNote(e.target.value)}
                      placeholder="Add a note..."
                      className="flex-1 text-sm bg-background border border-border-subtle rounded p-2 min-h-[60px] resize-none focus:outline-none focus:ring-1 focus:ring-accent"
                      autoFocus
                    />
                    <div className="flex flex-col gap-1">
                      <Button size="sm" onClick={() => saveNote(goal.id)} disabled={updateCase.isPending}>
                        <Save className="h-3 w-3 mr-1" /> Save
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setEditingNoteId(null)}>
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <>
                    {goal.note ? (
                      <div className="flex justify-between items-start group">
                        <p className="text-xs text-secondary bg-background/50 p-2 rounded border border-border-subtle flex-1 whitespace-pre-wrap">
                          {goal.note}
                        </p>
                        <button
                          onClick={() => { setEditingNoteId(goal.id); setDraftNote(goal.note!); }}
                          className="text-xs text-muted hover:text-accent ml-2 opacity-0 group-hover:opacity-100 transition-opacity flex items-center gap-1"
                        >
                          <Edit2 className="h-3 w-3" /> Edit
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => { setEditingNoteId(goal.id); setDraftNote(''); }}
                        className="text-xs text-muted hover:text-accent flex items-center gap-1 transition-colors self-start"
                      >
                        <Plus className="h-3 w-3" /> Add Note
                      </button>
                    )}
                  </>
                )}
              </div>
            </div>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Case Overview (FE-2) ────────────────────────────────────────────────────
function CaseOverview({ caseData, onTabChange }: { caseData: CaseResponse; onTabChange?: (tab: TabId) => void }) {
  const { data: acquisitions } = useAcquisitions(caseData.case_id);
  const { data: evidence } = useEvidence(caseData.case_id);

  const activeAcquisition = acquisitions?.items?.[0];

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
        <InvestigationGoalsChecklist caseData={caseData} />
      )}

      {/* Acquisition Section */}
      <AcquisitionSection
        caseId={caseData.case_id}
        acquisitions={acquisitions?.items || []}
        evidenceList={evidence?.items || []}
      />

      {/* Analysis Section */}
      <AnalysisSection
        caseId={caseData.case_id}
        acquisitionId={activeAcquisition?.acquisition_id}
        acquisitions={acquisitions?.items || []}
        onViewFindings={() => onTabChange?.('findings')}
      />

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

// ─── Investigation group tab panel ───────────────────────────────────────────
function InvestigationTabGroup({ caseId }: { caseId: string }) {
  const [sub, setSub] = useState<InvestigationSubTabId>('timeline');

  return (
    <div className="space-y-4">
      {/* Sub-tab bar */}
      <div
        className="flex border-b border-border-subtle overflow-x-auto"
        role="tablist"
        aria-label="Investigation sub-sections"
      >
        {INVESTIGATION_SUBTABS.map((t) => (
          <button
            key={t.id}
            role="tab"
            id={`investigation-subtab-${t.id}`}
            aria-selected={sub === t.id}
            aria-controls={`investigation-subpanel-${t.id}`}
            onClick={() => setSub(t.id)}
            className={`px-3 py-2 text-xs font-medium whitespace-nowrap border-b-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
              sub === t.id
                ? 'border-accent text-accent'
                : 'border-transparent text-secondary hover:text-primary hover:border-border-subtle'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Sub-tab panel */}
      <div
        role="tabpanel"
        id={`investigation-subpanel-${sub}`}
        aria-labelledby={`investigation-subtab-${sub}`}
      >
        {sub === 'timeline' && <TimelineSection caseId={caseId} />}
        {sub === 'entities' && <EntitiesSection caseId={caseId} />}
        {sub === 'relationships' && <RelationshipsSection caseId={caseId} />}
        {sub === 'behaviors' && <BehaviorsSection caseId={caseId} />}
        {sub === 'attack-chain' && <AttackChainSection caseId={caseId} />}
      </div>
    </div>
  );
}

// ─── Main page ───────────────────────────────────────────────────────────────
export function CaseDetailPage() {
  const { caseId } = useParams<{ caseId: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const defaultTab = (searchParams.get('tab') as TabId) || 'overview';
  const [activeTab, setActiveTab] = useState<TabId>(defaultTab);
  const [editing, setEditing] = useState(false);

  const handleTabChange = (tab: TabId) => {
    setActiveTab(tab);
    setSearchParams({ tab });
  };

  const { data: caseData, isLoading, isError, error, refetch } = useCaseQuery(caseId ?? '');
  const { data: acquisitions } = useAcquisitions(caseId ?? '');
  const { data: evidence } = useEvidence(caseId ?? '');

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
        {/* Acquisition & Evidence Status */}
        <AcquisitionSection
          caseId={caseData.case_id}
          acquisitions={acquisitions?.items || []}
          evidenceList={evidence?.items || []}
        />
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
                onClick={() => handleTabChange(tab.id)}
                className={`px-4 py-2.5 text-sm font-medium whitespace-nowrap border-b-2 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                  activeTab === tab.id
                    ? 'border-accent text-accent'
                    : 'border-transparent text-secondary hover:text-primary hover:border-border-subtle'
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>

          <div
            role="tabpanel"
            id={`panel-${activeTab}`}
            aria-labelledby={`tab-${activeTab}`}
          >
            {activeTab === 'overview' && <CaseOverview caseData={caseData} onTabChange={handleTabChange} />}
            {activeTab === 'findings' && <FindingsSection caseId={caseData.case_id} />}
            {activeTab === 'network' && <NetworkSection caseId={caseData.case_id} />}
            {activeTab === 'timeline' && <InvestigationTabGroup caseId={caseData.case_id} />}
            {activeTab === 'graph' && <GraphSection caseId={caseData.case_id} />}
            {activeTab === 'mitre' && <MitreSection caseId={caseData.case_id} />}
            {activeTab === 'evidence' && <EvidenceSection caseId={caseData.case_id} />}
            {activeTab === 'reports' && <ReportsSection caseId={caseData.case_id} />}
            {activeTab === 'copilot' && <CopilotPanel caseId={caseData.case_id} />}
          </div>
        </>
      )}
    </div>
  );
}
