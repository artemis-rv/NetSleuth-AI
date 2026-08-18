import { cn } from '../../lib/utils';
import { FileQuestion } from 'lucide-react';

interface EmptyStateProps {
  title: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

export function EmptyState({ title, description, action, className }: EmptyStateProps) {
  return (
    <div className={cn("flex flex-col items-center justify-center rounded-lg border border-dashed border-border-subtle p-8 text-center animate-in fade-in duration-500", className)}>
      <FileQuestion className="h-10 w-10 text-muted mb-4" />
      <h3 className="text-lg font-medium text-primary">{title}</h3>
      {description && <p className="text-sm text-muted mt-2 max-w-sm">{description}</p>}
      {action && <div className="mt-6">{action}</div>}
    </div>
  );
}
