import { cn } from '../../../lib/utils';

interface CaseStatusBadgeProps {
  status: string;
  className?: string;
}

const STATUS_STYLES: Record<string, string> = {
  OPEN: 'bg-info/15 text-info border-info/30',
  ACTIVE: 'bg-success/15 text-success border-success/30',
  UNDER_REVIEW: 'bg-warning/15 text-warning border-warning/30',
  CLOSED: 'bg-muted/20 text-muted border-muted/30',
  ARCHIVED: 'bg-muted/10 text-muted border-muted/20',
};

export function CaseStatusBadge({ status, className }: CaseStatusBadgeProps) {
  const style = STATUS_STYLES[status] ?? 'bg-muted/15 text-muted border-muted/30';
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium tracking-wide',
        style,
        className
      )}
      aria-label={`Status: ${status}`}
    >
      {status.replace('_', ' ')}
    </span>
  );
}

interface CasePriorityBadgeProps {
  priority?: string | null;
  className?: string;
}

const PRIORITY_STYLES: Record<string, string> = {
  CRITICAL: 'bg-danger/15 text-danger border-danger/30',
  HIGH: 'bg-warning/15 text-warning border-warning/30',
  MEDIUM: 'bg-info/15 text-info border-info/30',
  LOW: 'bg-muted/15 text-muted border-muted/30',
};

export function CasePriorityBadge({ priority, className }: CasePriorityBadgeProps) {
  if (!priority) return null;
  const style = PRIORITY_STYLES[priority] ?? 'bg-muted/15 text-muted border-muted/30';
  return (
    <span
      className={cn(
        'inline-flex items-center rounded border px-2 py-0.5 text-xs font-medium tracking-wide',
        style,
        className
      )}
      aria-label={`Priority: ${priority}`}
    >
      {priority}
    </span>
  );
}
