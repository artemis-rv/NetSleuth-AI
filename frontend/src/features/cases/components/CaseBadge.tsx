import { cn } from '../../../lib/utils';

interface CaseStatusBadgeProps {
  status: string;
  className?: string;
}

const STATUS_STYLES: Record<string, string> = {
  OPEN: 'bg-gradient-to-r from-info/25 to-info/10 text-info border-info/40 shadow-[0_0_10px_rgba(59,130,246,0.15)]',
  ACTIVE: 'bg-gradient-to-r from-success/25 to-success/10 text-success border-success/40 shadow-[0_0_10px_rgba(16,185,129,0.15)]',
  INVESTIGATING: 'bg-gradient-to-r from-success/25 to-success/10 text-success border-success/40 shadow-[0_0_10px_rgba(16,185,129,0.15)]',
  UNDER_REVIEW: 'bg-gradient-to-r from-warning/25 to-warning/10 text-warning border-warning/40 shadow-[0_0_10px_rgba(245,158,11,0.15)]',
  REVIEW: 'bg-gradient-to-r from-warning/25 to-warning/10 text-warning border-warning/40 shadow-[0_0_10px_rgba(245,158,11,0.15)]',
  CLOSED: 'bg-gradient-to-r from-muted/25 to-muted/10 text-muted border-muted/40',
  ARCHIVED: 'bg-gradient-to-r from-surface-elevated/80 to-surface-elevated/40 text-muted border-border-subtle',
};

const STATUS_DISPLAY: Record<string, string> = {
  OPEN: 'Open',
  ACTIVE: 'Active',
  INVESTIGATING: 'Investigating',
  UNDER_REVIEW: 'Under Review',
  REVIEW: 'Under Review',
  CLOSED: 'Closed',
  ARCHIVED: 'Archived',
};

export function CaseStatusBadge({ status, className }: CaseStatusBadgeProps) {
  const normalized = status ? status.toUpperCase() : '';
  const style = STATUS_STYLES[normalized] ?? 'bg-gradient-to-r from-muted/20 to-muted/5 text-muted border-muted/30';
  const label = STATUS_DISPLAY[normalized] ?? (status ? status.replace(/_/g, ' ') : '');
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2.5 py-0.5 text-[11px] uppercase font-bold tracking-widest backdrop-blur-sm transition-all duration-200',
        style,
        className
      )}
      aria-label={`Status: ${status}`}
    >
      {label}
    </span>
  );
}

interface CasePriorityBadgeProps {
  priority?: string | null;
  className?: string;
}

const PRIORITY_STYLES: Record<string, string> = {
  CRITICAL: 'bg-gradient-to-r from-danger/25 to-danger/10 text-danger border-danger/40 shadow-[0_0_10px_rgba(239,68,68,0.15)] text-shadow-sm',
  HIGH: 'bg-gradient-to-r from-warning/25 to-warning/10 text-warning border-warning/40 shadow-[0_0_10px_rgba(245,158,11,0.15)]',
  MEDIUM: 'bg-gradient-to-r from-info/25 to-info/10 text-info border-info/40 shadow-[0_0_10px_rgba(59,130,246,0.15)]',
  LOW: 'bg-gradient-to-r from-muted/25 to-muted/10 text-muted border-muted/40',
};

export function CasePriorityBadge({ priority, className }: CasePriorityBadgeProps) {
  if (!priority) return null;
  const normalized = priority.toUpperCase();
  const style = PRIORITY_STYLES[normalized] ?? 'bg-gradient-to-r from-muted/20 to-muted/5 text-muted border-muted/30';
  return (
    <span
      className={cn(
        'inline-flex items-center rounded-md border px-2.5 py-0.5 text-[11px] uppercase font-bold tracking-widest backdrop-blur-sm',
        style,
        className
      )}
      aria-label={`Priority: ${priority}`}
    >
      {priority}
    </span>
  );
}
