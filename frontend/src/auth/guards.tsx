import { Navigate, Outlet, useLocation } from 'react-router-dom';
import { useAuth } from './auth-context';
import { Spinner } from '../components/ui/Spinner';

export function ProtectedRoute() {
  const { state } = useAuth();
  const location = useLocation();

  if (state === 'authenticating' || state === 'logging_out') {
    return (
      <div className="flex h-screen w-full items-center justify-center bg-background">
        <div className="flex flex-col items-center">
          <Spinner size={32} className="mb-4" />
          <p className="text-sm text-muted">Authenticating...</p>
        </div>
      </div>
    );
  }

  if (state === 'unauthenticated') {
    return <Navigate to="/login" state={{ from: location }} replace />;
  }

  // authenticated
  return <Outlet />;
}

// Very basic role guard for future expansion
export function RoleRoute({ allowedRoles }: { allowedRoles: string[] }) {
  const { user } = useAuth();

  if (!user || !allowedRoles.includes(user.role)) {
    return <Navigate to="/403" replace />;
  }

  return <Outlet />;
}
