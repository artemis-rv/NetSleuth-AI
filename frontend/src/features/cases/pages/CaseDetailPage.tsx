import { useState, useMemo } from 'react';
import { useParams, Link, useSearchParams } from 'react-router-dom';
import { 
  ChevronLeft, Edit2, X, Calendar, Clock, User, Zap, Target, 
  CheckSquare, Square, Plus, Save, LayoutDashboard, AlertTriangle, 
  Activity, Share2, Shield, FolderOpen, FileText, Sparkles 
} from 'lucide-react';
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
    <div className="flex items-start gap-3 bg-surface/50 p-3 rounded-lg border border-border-subtle-2">
      <Icon className="h-4 w-4 text-muted mt-0.5 flex-shrink-0" aria-hidden="true" />
      <div>
        <p className="text-[11px] uppercase tracking-wider text-muted mb-1 font-semibold">{label}</p>
        <p className="text-sm font-medium text-primary">{value}</p>
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
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'network', label: 'Network', icon: Activity },
  { id: 'timeline', label: 'Timeline', icon: Clock },
  { id: 'graph', label: 'Graph', icon: Share2 },
  { id: 'mitre', label: 'MITRE', icon: Shield },
  { id: 'evidence', label: 'Evidence', icon: FolderOpen },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'copilot', label: 'AI Copilot', icon: Sparkles },
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
    <Card className="flex flex-col h-full border-border-subtle bg-surface-elevated/30">
      <CardHeader className="pb-2 border-b border-border-subtle/50 px-5 pt-5">
        <CardTitle className="text-sm flex items-center gap-2">
          <Target className="h-4 w-4 text-accent" aria-hidden="true" />
          Investigation Goals
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0 flex-1">
        <div className="divide-y divide-border-subtle/50" aria-label="Investigation goals">
          {goals.map((goal) => (
            <div key={goal.id} className="group flex flex-col p-4 transition-colors hover:bg-surface/50">
              <div className="flex items-start gap-3">
                <button
                  type="button"
                  onClick={() => toggleGoal(goal.id)}
                  className="mt-0.5 flex-shrink-0 text-muted hover:text-accent transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent rounded"
                  aria-label={goal.completed ? "Mark incomplete" : "Mark complete"}
                >
                  {goal.completed ? (
                    <CheckSquare className="h-5 w-5 text-success" />
                  ) : (
                    <Square className="h-5 w-5 text-muted group-hover:text-primary transition-colors" />
                  )}
                </button>
                <div className="flex-1">
                  <span className={`text-[14px] leading-relaxed font-medium transition-colors ${goal.completed ? 'text-muted line-through' : 'text-primary'}`}>
                    {goal.description}
                  </span>
                </div>
              </div>
              
              <div className="pl-8 mt-1.5 flex flex-col">
                {editingNoteId === goal.id ? (
                  <div className="flex gap-2 items-start mt-2 bg-background/50 p-2 rounded-md border border-border-subtle">
                    <textarea
                      value={draftNote}
                      onChange={(e) => setDraftNote(e.target.value)}
                      placeholder="Add an investigator note..."
                      className="flex-1 text-sm bg-transparent border-none min-h-[40px] resize-none focus:outline-none focus:ring-0 text-primary"
                      autoFocus
                    />
                    <div className="flex flex-col gap-1.5">
                      <Button size="sm" onClick={() => saveNote(goal.id)} disabled={updateCase.isPending} className="h-7 text-xs">
                        <Save className="h-3 w-3 mr-1" /> Save
                      </Button>
                      <Button size="sm" variant="ghost" onClick={() => setEditingNoteId(null)} className="h-7 text-xs">
                        Cancel
                      </Button>
                    </div>
                  </div>
                ) : (
                  <>
                    {goal.note ? (
                      <div className="flex justify-between items-start group/note mt-1">
                        <p className="text-[13px] text-secondary border-l-2 border-accent/40 pl-3 py-0.5 flex-1 whitespace-pre-wrap">
                          {goal.note}
                        </p>
                        <button
                          onClick={() => { setEditingNoteId(goal.id); setDraftNote(goal.note!); }}
                          className="text-xs text-muted hover:text-accent ml-2 opacity-0 group-hover/note:opacity-100 transition-opacity flex items-center gap-1"
                        >
                          <Edit2 className="h-3 w-3" /> Edit
                        </button>
                      </div>
                    ) : (
                      <button
                        onClick={() => { setEditingNoteId(goal.id); setDraftNote(''); }}
                        className="text-xs text-muted hover:text-accent flex items-center gap-1.5 transition-colors self-start mt-1 opacity-0 group-hover:opacity-100"
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
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 lg:gap-6 items-start">
      {/* Trigger Panel */}
      <Card className="flex flex-col h-full border-border-subtle bg-surface-elevated/30">
        <CardHeader className="pb-2 border-b border-border-subtle/50 px-5 pt-5">
          <CardTitle className="text-sm flex items-center gap-2">
            <Zap className="h-4 w-4 text-warning" aria-hidden="true" />
            Triggering Event
          </CardTitle>
        </CardHeader>
        <CardContent className="px-5 py-4 flex-1">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
            <div>
              <p className="text-[11px] uppercase tracking-wider text-muted mb-2 font-semibold">Trigger Type</p>
              <span className="inline-flex items-center rounded border border-border-subtle bg-surface px-2.5 py-1 text-xs font-medium text-secondary shadow-sm">
                {caseData.trigger_type.replace(/_/g, ' ')}
              </span>
            </div>
            {caseData.trigger_description && (
              <div className="md:col-span-2">
                <p className="text-[11px] uppercase tracking-wider text-muted mb-2 font-semibold">Context / Description</p>
                <p className="text-sm text-primary whitespace-pre-wrap leading-relaxed bg-surface/50 p-3 rounded-md border border-border-subtle-2">
                  {caseData.trigger_description}
                </p>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* Investigation Goals Panel or Case Notes */}
      {caseData.investigation_goals && caseData.investigation_goals.length > 0 ? (
        <InvestigationGoalsChecklist caseData={caseData} />
      ) : (
        <Card className="flex flex-col h-full border-border-subtle bg-surface-elevated/30">
          <CardHeader className="pb-2 border-b border-border-subtle/50 px-5 pt-5">
            <CardTitle className="text-sm flex items-center gap-2">
              <FileText className="h-4 w-4 text-info" aria-hidden="true" />
              Case Notes
            </CardTitle>
          </CardHeader>
          <CardContent className="px-5 py-4 flex-1">
            {caseData.description ? (
              <p className="text-sm text-primary whitespace-pre-wrap leading-relaxed bg-surface/50 p-3 rounded-md border border-border-subtle-2">
                {caseData.description}
              </p>
            ) : (
              <div className="flex flex-col items-center justify-center h-full text-center py-6">
                <FileText className="h-8 w-8 text-muted/50 mb-3" />
                <p className="text-sm text-muted">No notes or description available.</p>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Acquisition Section */}
      <div className="lg:col-span-1 flex flex-col h-full">
        <AcquisitionSection
          caseId={caseData.case_id}
          acquisitions={acquisitions?.items || []}
          evidenceList={evidence?.items || []}
        />
      </div>

      {/* Metadata Panel */}
      <div className="lg:col-span-1 flex flex-col h-full">
        <Card className="flex flex-col h-full border-border-subtle bg-surface-elevated/30">
          <CardHeader className="pb-2 border-b border-border-subtle/50 px-5 pt-5">
            <CardTitle className="text-sm flex items-center gap-2">
              <Activity className="h-4 w-4 text-accent" aria-hidden="true" />
              Case Metadata
            </CardTitle>
          </CardHeader>
          <CardContent className="px-5 py-4 flex-1">
            <div className="grid grid-cols-2 xl:grid-cols-3 gap-x-4 gap-y-5">
              <MetaItem icon={Calendar} label="Opened" value={formatDateTime(caseData.opened_at)} />
              <MetaItem icon={Clock} label="Last Updated" value={formatDateTime(caseData.updated_at)} />
              {caseData.closed_at && (
                <MetaItem icon={Calendar} label="Closed" value={formatDateTime(caseData.closed_at)} />
              )}
              <MetaItem icon={User} label="Reported By" value={caseData.reported_by} />
              <MetaItem icon={FolderOpen} label="External ID" value={caseData.external_case_id} />
              <MetaItem icon={Target} label="Source System" value={caseData.external_system} />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Analysis Section (Full width bottom) */}
      <div className="lg:col-span-2">
        <AnalysisSection
          caseId={caseData.case_id}
          acquisitionId={activeAcquisition?.acquisition_id}
          acquisitions={acquisitions?.items || []}
          onViewFindings={() => onTabChange?.('findings')}
        />
      </div>
    </div>
  );
}

// ─── Investigation group tab panel ───────────────────────────────────────────
function InvestigationTabGroup({ caseId }: { caseId: string }) {
  const [sub, setSub] = useState<InvestigationSubTabId>('timeline');

  return (
    <div className="space-y-4">
      {/* Segmented Control Sub-tab bar (With outer box) */}
      <div className="flex">
        <div
          className="inline-flex items-center gap-1 p-1 bg-surface-elevated/30 border border-border-subtle rounded-xl overflow-x-auto no-scrollbar shadow-sm"
          role="tablist"
          aria-label="Investigation sub-sections"
        >
          {INVESTIGATION_SUBTABS.map((t) => {
            const isActive = sub === t.id;
            return (
              <button
                key={t.id}
                role="tab"
                id={`investigation-subtab-${t.id}`}
                aria-selected={isActive}
                aria-controls={`investigation-subpanel-${t.id}`}
                onClick={() => setSub(t.id)}
                className={`relative px-4 py-1.5 text-xs rounded-lg whitespace-nowrap transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
                  isActive
                    ? 'text-primary font-semibold bg-surface border border-border-subtle/80 shadow-[0_2px_8px_rgba(0,0,0,0.12)]'
                    : 'text-muted font-medium hover:text-primary hover:bg-surface/50 border border-transparent'
                }`}
              >
                {isActive && (
                  <div className="absolute bottom-0 left-1/2 -translate-x-1/2 w-1/3 h-[2px] bg-gradient-to-r from-transparent via-accent to-transparent opacity-70 rounded-t-full shadow-[0_-2px_6px_rgba(59,130,246,0.5)]" />
                )}
                {t.label}
              </button>
            );
          })}
        </div>
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
  const { caseId, tab } = useParams<{ caseId: string, tab?: string }>();
  const activeTab = (tab as TabId) || 'overview';
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
    <div className="max-w-[1600px] mx-auto px-4 md:px-6 lg:px-8 py-6">
      {/* Compact Case Header */}
      <div className="mb-6 flex flex-col gap-3">
        <div className="flex justify-end">
          <Button
            variant="secondary"
            size="sm"
            className="border-border-subtle bg-surface hover:bg-surface-elevated text-primary h-7 px-3 text-xs shadow-sm transition-all"
            onClick={() => setEditing((prev) => !prev)}
            aria-label={editing ? 'Cancel editing' : 'Edit case'}
          >
            {editing ? (
              <><X className="h-3.5 w-3.5 mr-1.5 text-muted" aria-hidden="true" /> Cancel</>
            ) : (
              <><Edit2 className="h-3.5 w-3.5 mr-1.5 text-muted" aria-hidden="true" /> Edit</>
            )}
          </Button>
        </div>

        {/* Identity Card */}
        <div className="relative bg-surface-elevated/20 border border-border-subtle rounded-lg p-4 md:p-5 overflow-hidden shadow-sm">
          {/* Accent Bar */}
          <div className="absolute left-0 top-0 bottom-0 w-1 bg-accent/60"></div>

          <div className="flex flex-col gap-3 ml-1">
            {/* Badges & Title */}
            <div className="flex items-center gap-3 flex-wrap">
              <div className="flex items-center gap-2">
                <CaseStatusBadge status={caseData.status} />
                <CasePriorityBadge priority={caseData.priority} />
              </div>
              <h1 className="text-xl md:text-2xl font-bold tracking-tight text-white leading-none shadow-sm">
                {caseData.title}
              </h1>
            </div>

            {/* Description */}
            {caseData.description && (
              <p className="text-[14px] text-secondary/90 truncate max-w-4xl font-medium" title={caseData.description}>
                {caseData.description}
              </p>
            )}

            {/* Case ID */}
            <div className="flex items-center gap-2.5 mt-1">
              <span className="text-[10px] uppercase tracking-widest text-muted font-bold flex items-center gap-1.5">
                <Shield className="h-3 w-3" aria-hidden="true" />
                Case ID
              </span>
              <span className="text-[11px] text-secondary font-mono bg-background/60 px-2 py-0.5 rounded border border-border-subtle shadow-inner">
                {caseData.case_id}
              </span>
            </div>
          </div>
        </div>
      </div>
      {/* Edit Form */}
      {editing && (
        <Card className="mb-8 border-border-subtle bg-surface-elevated/30">
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
            role="tabpanel"
            id={`panel-${activeTab}`}
            aria-labelledby={`tab-${activeTab}`}
            className="min-h-[500px]"
          >
            {activeTab === 'overview' && <CaseOverview caseData={caseData} />}
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
