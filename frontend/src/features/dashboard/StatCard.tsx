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
      <div className="relative overflow-hidden rounded-xl border border-border-subtle bg-surface-elevated/20 p-5 animate-pulse shadow-sm">
        <div className="h-3 w-24 bg-surface-elevated rounded mb-3" />
        <div className="h-8 w-16 bg-surface-elevated rounded mb-2" />
        <div className="h-3 w-32 bg-surface-elevated rounded" />
      </div>
    );
  }

  return (
    <div
      className={cn(
        'relative overflow-hidden rounded-xl border bg-gradient-to-br from-surface-elevated/40 to-surface/20 p-5 backdrop-blur-sm transition-all duration-300 hover:shadow-lg hover:-translate-y-0.5 group shadow-sm',
        variant === 'default' && 'border-border-subtle hover:border-border-subtle/80',
        variant === 'warning' && 'border-warning/30 hover:border-warning/50',
        variant === 'danger' && 'border-danger/30 hover:border-danger/50',
        variant === 'info' && 'border-info/30 hover:border-info/50',
      )}
    >
      {/* Subtle top glow effect */}
      <div className={cn(
        "absolute top-0 left-0 right-0 h-[1px] opacity-30 group-hover:opacity-60 transition-opacity duration-300",
        variant === 'default' && 'bg-gradient-to-r from-transparent via-white/50 to-transparent',
        variant === 'warning' && 'bg-gradient-to-r from-transparent via-warning to-transparent',
        variant === 'danger' && 'bg-gradient-to-r from-transparent via-danger to-transparent',
        variant === 'info' && 'bg-gradient-to-r from-transparent via-info to-transparent',
      )} />

      <p className="text-xs font-semibold text-muted uppercase tracking-wider mb-2 drop-shadow-sm">{title}</p>
      <p
        className={cn(
          'text-4xl font-bold tabular-nums tracking-tight',
          variant === 'default' && 'text-primary drop-shadow-md',
          variant === 'warning' && 'text-warning drop-shadow-[0_0_12px_rgba(245,158,11,0.4)]',
          variant === 'danger' && 'text-danger drop-shadow-[0_0_12px_rgba(239,68,68,0.4)]',
          variant === 'info' && 'text-info drop-shadow-[0_0_12px_rgba(59,130,246,0.4)]',
        )}
      >
        {value}
      </p>
      {description && (
        <p className="text-xs text-secondary/80 mt-1.5 font-medium">{description}</p>
      )}
    </div>
  );
}
