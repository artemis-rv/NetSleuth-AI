import { EmptyState } from '../components/feedback/EmptyState';
import { Button } from '../components/ui/Button';
import { Link } from 'react-router-dom';

export function NotFoundPage() {
  return (
    <div className="flex h-full w-full items-center justify-center p-8">
      <EmptyState
        title="Page not found"
        description="The page you are looking for does not exist or has been moved."
        action={
          <Link to="/">
            <Button variant="primary">Return Home</Button>
          </Link>
        }
      />
    </div>
  );
}

export function ForbiddenPage() {
  return (
    <div className="flex h-full w-full items-center justify-center p-8">
      <EmptyState
        title="Access Denied"
        description="You do not have permission to view this resource."
        action={
          <Link to="/">
            <Button variant="primary">Return Home</Button>
          </Link>
        }
      />
    </div>
  );
}

export function DashboardPlaceholder() {
  return (
    <div>
      <h1 className="text-2xl font-bold tracking-tight mb-6">Dashboard</h1>
      <div className="grid gap-6 grid-cols-1 md:grid-cols-2 lg:grid-cols-3">
        <EmptyState 
          title="Dashboard View" 
          description="Business logic and investigation data will be implemented in future phases." 
          className="col-span-full h-64"
        />
      </div>
    </div>
  );
}
