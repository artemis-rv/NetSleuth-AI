import { AlertCircle } from 'lucide-react';
import { ApiError } from '../../api/errors';
import { Button } from '../ui/Button';
import { cn } from '../../lib/utils';

interface ErrorStateProps {
  error: Error | ApiError;
  retry?: () => void;
  className?: string;
}

export function ErrorState({ error, retry, className }: ErrorStateProps) {
  const isApiError = error instanceof ApiError;
  
  return (
    <div className={cn("flex flex-col items-center justify-center p-8 text-center bg-surface-elevated rounded-lg border border-danger/30", className)}>
      <AlertCircle className="h-10 w-10 text-danger mb-4" />
      <h3 className="text-lg font-medium text-primary mb-2">Something went wrong</h3>
      <p className="text-sm text-secondary max-w-md mb-2">{error.message}</p>
      
      {isApiError && error.requestId && (
        <p className="text-xs text-muted mb-4 font-mono">Request ID: {error.requestId}</p>
      )}
      
      {retry && (
        <Button onClick={retry} variant="secondary" className="mt-4">
          Try Again
        </Button>
      )}
    </div>
  );
}
