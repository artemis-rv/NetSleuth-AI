import { useState } from 'react';
import { X, Plus } from 'lucide-react';
import { useUpdateCaseMutation } from '../hooks';
import { TRIGGER_TYPES, CASE_PRIORITIES, CASE_STATUSES, CASE_STATUS_LABELS, CASE_PRIORITY_LABELS, ALLOWED_STATUS_TRANSITIONS } from '../types';
import type { CaseResponse, UpdateCaseRequest } from '../types';
import { Button } from '../../../components/ui/Button';
import { Input } from '../../../components/ui/Input';
import { Alert } from '../../../components/feedback/Alert';
import { ApiError } from '../../../api/errors';

interface EditCaseFormProps {
  caseData: CaseResponse;
  onSuccess?: (updated: CaseResponse) => void;
  onCancel?: () => void;
}

export function EditCaseForm({ caseData, onSuccess, onCancel }: EditCaseFormProps) {
  const mutation = useUpdateCaseMutation(caseData.case_id);

  const [title, setTitle] = useState(caseData.title);
  const [description, setDescription] = useState(caseData.description ?? '');
  const [priority, setPriority] = useState(caseData.priority ?? '');
  const [status, setStatus] = useState(caseData.status);
  const [triggerType, setTriggerType] = useState(caseData.trigger_type);
  const [triggerDescription, setTriggerDescription] = useState(caseData.trigger_description ?? '');
  const [reportedBy, setReportedBy] = useState(caseData.reported_by ?? '');
  const [goals, setGoals] = useState<string[]>(() => {
    if (!caseData.investigation_goals?.length) return [''];
    return caseData.investigation_goals.map((g) => (typeof g === 'string' ? g : g.description || ''));
  });
  const [error, setError] = useState('');
  const [titleError, setTitleError] = useState('');

  const handleGoalChange = (idx: number, value: string) => {
    setGoals(goals.map((g, i) => (i === idx ? value : g)));
  };
  const addGoal = () => setGoals([...goals, '']);
  const removeGoal = (idx: number) => {
    const next = goals.filter((_, i) => i !== idx);
    setGoals(next.length === 0 ? [''] : next);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setTitleError('');
    if (!title.trim()) {
      setTitleError('Title is required');
      return;
    }

    const filteredGoals = goals.map((g) => g.trim()).filter(Boolean);
    const payload: UpdateCaseRequest = {
      title: title.trim() || null,
      description: description.trim() || null,
      priority: priority || null,
      status: status || null,
      trigger_type: triggerType || null,
      trigger_description: triggerDescription.trim() || null,
      investigation_goals: filteredGoals.length > 0 ? filteredGoals : null,
      reported_by: reportedBy.trim() || null,
    };

    try {
      const updated = await mutation.mutateAsync(payload);
      onSuccess?.(updated);
    } catch (err) {
      if (err instanceof ApiError) {
        setError(err.message);
      } else {
        setError('Update failed. Please try again.');
      }
    }
  };

  return (
    <form onSubmit={handleSubmit} noValidate aria-label="Edit case form">
      <div className="space-y-6">
        {error && <Alert variant="error">{error}</Alert>}

        <div className="grid grid-cols-1 gap-4">
          <div>
            <label htmlFor="edit-title" className="block text-sm font-medium text-primary mb-1">
              Title <span className="text-danger" aria-hidden="true">*</span>
            </label>
            <Input
              id="edit-title"
              type="text"
              value={title}
              onChange={(e) => { setTitle(e.target.value); setTitleError(''); }}
              aria-required="true"
              aria-invalid={!!titleError}
            />
            {titleError && <p className="mt-1 text-xs text-danger" role="alert">{titleError}</p>}
          </div>

          <div>
            <label htmlFor="edit-description" className="block text-sm font-medium text-primary mb-1">
              Description
            </label>
            <textarea
              id="edit-description"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={3}
              className="flex w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-primary placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent resize-y"
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label htmlFor="edit-status" className="block text-sm font-medium text-primary mb-1">
                Status
              </label>
              <select
                id="edit-status"
                value={status}
                onChange={(e) => setStatus(e.target.value)}
                className="flex h-10 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent transition-all duration-200"
              >
                {CASE_STATUSES.map((s) => {
                  const currentNorm = (caseData?.status || '').toLowerCase();
                  const allowed = ALLOWED_STATUS_TRANSITIONS[currentNorm] || [];
                  const isCurrent = s === currentNorm;
                  const isTransitionAllowed = allowed.includes(s) || allowed.length === 0;
                  return (
                    <option
                      key={s}
                      value={s}
                      disabled={!isCurrent && !isTransitionAllowed}
                    >
                      {CASE_STATUS_LABELS[s] ?? s.replace(/_/g, ' ')}{isCurrent ? ' (Current)' : ''}
                    </option>
                  );
                })}
              </select>
            </div>
            <div>
              <label htmlFor="edit-priority" className="block text-sm font-medium text-primary mb-1">
                Priority
              </label>
              <select
                id="edit-priority"
                value={priority}
                onChange={(e) => setPriority(e.target.value)}
                className="flex h-10 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent transition-all duration-200"
              >
                <option value="">— Not set —</option>
                {CASE_PRIORITIES.map((p) => (
                  <option key={p} value={p}>{CASE_PRIORITY_LABELS[p] ?? p}</option>
                ))}
              </select>
            </div>
          </div>

          <div>
            <label htmlFor="edit-trigger-type" className="block text-sm font-medium text-primary mb-1">
              Trigger Type
            </label>
            <select
              id="edit-trigger-type"
              value={triggerType}
              onChange={(e) => setTriggerType(e.target.value)}
              className="flex h-10 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
            >
              {TRIGGER_TYPES.map((t) => (
                <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
              ))}
            </select>
          </div>

          <div>
            <label htmlFor="edit-trigger-description" className="block text-sm font-medium text-primary mb-1">
              Trigger Description
            </label>
            <textarea
              id="edit-trigger-description"
              value={triggerDescription}
              onChange={(e) => setTriggerDescription(e.target.value)}
              rows={3}
              className="flex w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-primary placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent resize-y"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-primary mb-2">
              Investigation Goals
            </label>
            <div className="space-y-2" role="list">
              {goals.map((goal, idx) => (
                <div key={idx} className="flex items-center gap-2" role="listitem">
                  <span className="text-xs text-muted w-5 text-right" aria-hidden="true">{idx + 1}.</span>
                  <Input
                    type="text"
                    value={goal}
                    onChange={(e) => handleGoalChange(idx, e.target.value)}
                    aria-label={`Goal ${idx + 1}`}
                    className="flex-1"
                  />
                  <button
                    type="button"
                    onClick={() => removeGoal(idx)}
                    className="p-1.5 text-muted hover:text-danger transition-colors rounded"
                    aria-label={`Remove goal ${idx + 1}`}
                    disabled={goals.length === 1}
                  >
                    <X className="h-4 w-4" />
                  </button>
                </div>
              ))}
            </div>
            <Button type="button" variant="ghost" size="sm" onClick={addGoal} className="mt-2 text-accent">
              <Plus className="h-4 w-4 mr-1" /> Add Goal
            </Button>
          </div>

          <div>
            <label htmlFor="edit-reported-by" className="block text-sm font-medium text-primary mb-1">
              Reported By
            </label>
            <Input
              id="edit-reported-by"
              type="text"
              value={reportedBy}
              onChange={(e) => setReportedBy(e.target.value)}
            />
          </div>
        </div>

        <div className="flex items-center justify-end gap-3 pt-4 border-t border-border-subtle">
          <Button type="button" variant="ghost" onClick={onCancel}>
            Cancel
          </Button>
          <Button type="submit" disabled={mutation.isPending} aria-busy={mutation.isPending}>
            {mutation.isPending ? 'Saving…' : 'Save Changes'}
          </Button>
        </div>
      </div>
    </form>
  );
}
