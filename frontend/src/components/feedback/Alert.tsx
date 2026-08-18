import { AlertCircle, CheckCircle, Info, XCircle } from 'lucide-react';
import { cn } from '../../lib/utils';

interface AlertProps extends React.HTMLAttributes<HTMLDivElement> {
  variant?: 'info' | 'success' | 'warning' | 'error';
  title?: string;
  children: React.ReactNode;
}

export function Alert({ variant = 'info', title, children, className, ...props }: AlertProps) {
  const Icon = {
    info: Info,
    success: CheckCircle,
    warning: AlertCircle,
    error: XCircle
  }[variant];

  return (
    <div
      className={cn(
        'relative w-full rounded-lg border p-4 [&>svg]:absolute [&>svg]:text-foreground [&>svg]:left-4 [&>svg]:top-4 [&>svg+div]:translate-y-[-3px] [&:has(svg)]:pl-11',
        {
          'bg-surface-elevated text-primary border-info/50 [&>svg]:text-info': variant === 'info',
          'bg-surface-elevated text-primary border-success/50 [&>svg]:text-success': variant === 'success',
          'bg-surface-elevated text-primary border-warning/50 [&>svg]:text-warning': variant === 'warning',
          'bg-surface-elevated text-primary border-danger/50 [&>svg]:text-danger': variant === 'error',
        },
        className
      )}
      {...props}
    >
      <Icon className="h-4 w-4 mt-0.5" />
      {title && <h5 className="mb-1 font-medium leading-none tracking-tight">{title}</h5>}
      <div className="text-sm [&_p]:leading-relaxed opacity-90">{children}</div>
    </div>
  );
}
