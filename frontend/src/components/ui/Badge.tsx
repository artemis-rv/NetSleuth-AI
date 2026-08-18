import { cn } from '../../lib/utils';

interface BadgeProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
}

export function Badge({ className, variant = 'default', ...props }: BadgeProps) {
  return (
    <div
      className={cn(
        'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-accent',
        {
          'border-transparent bg-surface-elevated text-primary': variant === 'default',
          'border-transparent bg-success/20 text-success': variant === 'success',
          'border-transparent bg-warning/20 text-warning': variant === 'warning',
          'border-transparent bg-danger/20 text-danger': variant === 'danger',
          'border-transparent bg-info/20 text-info': variant === 'info',
        },
        className
      )}
      {...props}
    />
  );
}
