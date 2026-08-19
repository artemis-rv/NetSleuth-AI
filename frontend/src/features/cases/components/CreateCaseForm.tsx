import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Target, Plus, X } from 'lucide-react';
import { useCreateCaseMutation } from '../hooks';
import { TRIGGER_TYPES, CASE_PRIORITIES } from '../types';
import type { CreateCaseRequest } from '../types';
import { Button } from '../../../components/ui/Button';
import { Input } from '../../../components/ui/Input';
import { Alert } from '../../../components/feedback/Alert';
import { ApiError } from '../../../api/errors';

interface FormErrors {
  title?: string;
  trigger_type?: string;
  general?: string;
}

export function CreateCaseForm() {
  const navigate = useNavigate();
  const mutation = useCreateCaseMutation();

  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [triggerType, setTriggerType] = useState('');
  const [triggerDescription, setTriggerDescription] = useState('');
  const [priority, setPriority] = useState('');
  const [reportedBy, setReportedBy] = useState('');
  const [goals, setGoals] = useState<string[]>(['']);
  const [errors, setErrors] = useState<FormErrors>({});

  const validate = (): boolean => {
    const newErrors: FormErrors = {};
    if (!title.trim()) newErrors.title = 'Title is required';
    if (!triggerType) newErrors.trigger_type = 'Trigger type is required';
    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

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
    if (!validate()) return;

    // Preserve investigator-entered wording; filter blank goals
    const filteredGoals = goals.map((g) => g.trim()).filter(Boolean);

    const payload: CreateCaseRequest = {
      title: title.trim(),
      trigger_type: triggerType,
    };
    if (description.trim()) payload.description = description.trim();
    if (triggerDescription.trim()) payload.trigger_description = triggerDescription.trim();
    if (filteredGoals.length > 0) {
      payload.investigation_goals = filteredGoals.map(g => ({
        id: crypto.randomUUID(),
        description: g,
        completed: false,
        note: null
      }));
    }
    if (priority) payload.priority = priority;
    if (reportedBy.trim()) payload.reported_by = reportedBy.trim();

    try {
      const created = await mutation.mutateAsync(payload);
      navigate(`/investigations/${created.case_id}?tab=network`);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 422 && err.details) {
          // Map FastAPI validation errors to fields
          const fieldErrors: FormErrors = {};
          for (const detail of err.details) {
            const field = detail.loc?.[detail.loc.length - 1];
            if (field === 'title') fieldErrors.title = detail.msg;
            else if (field === 'trigger_type') fieldErrors.trigger_type = detail.msg;
            else fieldErrors.general = detail.msg;
          }
          setErrors(fieldErrors);
        } else if (err.status === 403) {
          setErrors({ general: 'You do not have permission to create investigations.' });
        } else {
          setErrors({ general: err.message });
        }
      } else {
        setErrors({ general: 'An unexpected error occurred. Please try again.' });
      }
    }
  };

  return (
    <form onSubmit={handleSubmit} noValidate aria-label="Create investigation form">
      <div className="space-y-8">
        {/* General error */}
        {errors.general && (
          <Alert variant="error">{errors.general}</Alert>
        )}

        {/* Section: Case Identity */}
        <section aria-labelledby="identity-heading">
          <h2 id="identity-heading" className="text-base font-semibold text-primary mb-4 pb-2 border-b border-border-subtle">
            Case Identity
          </h2>
          <div className="space-y-4">
            <div>
              <label htmlFor="case-title" className="block text-sm font-medium text-primary mb-1">
                Title <span className="text-danger" aria-hidden="true">*</span>
              </label>
              <Input
                id="case-title"
                type="text"
                value={title}
                onChange={(e) => { setTitle(e.target.value); setErrors((p) => ({ ...p, title: undefined })); }}
                placeholder="e.g. Suspicious outbound traffic — Workstation 14"
                aria-required="true"
                aria-invalid={!!errors.title}
                aria-describedby={errors.title ? 'title-error' : undefined}
                autoFocus
              />
              {errors.title && (
                <p id="title-error" className="mt-1 text-xs text-danger" role="alert">{errors.title}</p>
              )}
            </div>

            <div>
              <label htmlFor="case-description" className="block text-sm font-medium text-primary mb-1">
                Description
              </label>
              <textarea
                id="case-description"
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Optional case context and background…"
                rows={3}
                className="flex w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-primary placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent disabled:opacity-50 resize-y"
              />
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <label htmlFor="case-priority" className="block text-sm font-medium text-primary mb-1">
                  Priority
                </label>
                <select
                  id="case-priority"
                  value={priority}
                  onChange={(e) => setPriority(e.target.value)}
                  className="flex h-10 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                >
                  <option value="">— Not set —</option>
                  {CASE_PRIORITIES.map((p) => (
                    <option key={p} value={p}>{p.toUpperCase()}</option>
                  ))}
                </select>
              </div>
              <div>
                <label htmlFor="reported-by" className="block text-sm font-medium text-primary mb-1">
                  Reported By
                </label>
                <Input
                  id="reported-by"
                  type="text"
                  value={reportedBy}
                  onChange={(e) => setReportedBy(e.target.value)}
                  placeholder="Name or system…"
                />
              </div>
            </div>
          </div>
        </section>

        {/* Section: Triggering Event */}
        <section aria-labelledby="trigger-heading">
          <h2 id="trigger-heading" className="text-base font-semibold text-primary mb-4 pb-2 border-b border-border-subtle">
            Triggering Event
          </h2>
          <div className="space-y-4">
            <div>
              <label htmlFor="trigger-type" className="block text-sm font-medium text-primary mb-1">
                Trigger Type <span className="text-danger" aria-hidden="true">*</span>
              </label>
              <select
                id="trigger-type"
                value={triggerType}
                onChange={(e) => { setTriggerType(e.target.value); setErrors((p) => ({ ...p, trigger_type: undefined })); }}
                aria-required="true"
                aria-invalid={!!errors.trigger_type}
                aria-describedby={errors.trigger_type ? 'trigger-type-error' : undefined}
                className="flex h-10 w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-primary focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
              >
                <option value="">— Select trigger type —</option>
                {TRIGGER_TYPES.map((t) => (
                  <option key={t} value={t}>{t.replace(/_/g, ' ')}</option>
                ))}
              </select>
              {errors.trigger_type && (
                <p id="trigger-type-error" className="mt-1 text-xs text-danger" role="alert">{errors.trigger_type}</p>
              )}
            </div>

            <div>
              <label htmlFor="trigger-description" className="block text-sm font-medium text-primary mb-1">
                Trigger Description
              </label>
              <textarea
                id="trigger-description"
                value={triggerDescription}
                onChange={(e) => setTriggerDescription(e.target.value)}
                placeholder="Describe the event that triggered this investigation in your own words…"
                rows={4}
                className="flex w-full rounded-md border border-border-subtle bg-surface px-3 py-2 text-sm text-primary placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent resize-y"
              />
              <p className="mt-1 text-xs text-muted">
                Your exact wording is preserved — do not summarize or omit context.
              </p>
            </div>
          </div>
        </section>

        {/* Section: Investigation Goals */}
        <section aria-labelledby="goals-heading">
          <h2 id="goals-heading" className="text-base font-semibold text-primary mb-4 pb-2 border-b border-border-subtle flex items-center gap-2">
            <Target className="h-4 w-4 text-accent" aria-hidden="true" />
            Investigation Goals
          </h2>
          <div className="space-y-2" role="list" aria-label="Investigation goals">
            {goals.map((goal, idx) => (
              <div key={idx} className="flex items-center gap-2" role="listitem">
                <span className="text-xs text-muted w-5 text-right select-none" aria-hidden="true">
                  {idx + 1}.
                </span>
                <Input
                  type="text"
                  value={goal}
                  onChange={(e) => handleGoalChange(idx, e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter') {
                      e.preventDefault();
                      if (idx === goals.length - 1) {
                        addGoal();
                        // Focus will need a slight delay to allow React to render the new input,
                        // or we can rely on the user tabbing. For simplicity, just add the goal.
                      }
                    }
                  }}
                  placeholder={`e.g. Identify the source of lateral movement`}
                  aria-label={`Investigation goal ${idx + 1}`}
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
          <Button
            type="button"
            variant="ghost"
            size="sm"
            onClick={addGoal}
            className="mt-3 text-accent hover:text-accent/80"
          >
            <Plus className="h-4 w-4 mr-1" />
            Add Goal
          </Button>
        </section>

        {/* Actions */}
        <div className="flex items-center justify-end gap-3 pt-4 border-t border-border-subtle">
          <Button
            type="button"
            variant="ghost"
            onClick={() => navigate('/investigations')}
          >
            Cancel
          </Button>
          <Button
            type="submit"
            disabled={mutation.isPending}
            aria-busy={mutation.isPending}
          >
            {mutation.isPending ? 'Creating…' : 'Create Investigation'}
          </Button>
        </div>
      </div>
    </form>
  );
}
