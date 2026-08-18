import { cn } from '../../lib/utils';

interface StatCardProps {
  title: string;
  value: number | string;
  description?: string;
  variant?: 'default' | 'warning' | 'danger' | 'info';
  loading?: boolean;
}

export function StatCard({ title, value, description, variant = 'default', loading = false }: StatCardProps) {
  if (loading) {
    return (
      <div className="rounded-lg border border-border-subtle bg-surface p-5 animate-pulse">
        <div className="h-3 w-24 bg-surface-elevated rounded mb-3" />
        <div className="h-8 w-16 bg-surface-elevated rounded mb-2" />
        <div className="h-3 w-32 bg-surface-elevated rounded" />
      </div>
    );
  }

  return (
    <div
      className={cn(
        'rounded-lg border bg-surface p-5 transition-colors',
        variant === 'default' && 'border-border-subtle',
        variant === 'warning' && 'border-warning/30',
        variant === 'danger' && 'border-danger/30',
        variant === 'info' && 'border-info/30',
      )}
    >
      <p className="text-xs font-medium text-muted uppercase tracking-wider mb-2">{title}</p>
      <p
        className={cn(
          'text-3xl font-bold tabular-nums',
          variant === 'default' && 'text-primary',
          variant === 'warning' && 'text-warning',
          variant === 'danger' && 'text-danger',
          variant === 'info' && 'text-info',
        )}
      >
        {value}
      </p>
      {description && (
        <p className="text-xs text-muted mt-1">{description}</p>
      )}
    </div>
  );
}
