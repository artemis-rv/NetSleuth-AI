import { Link, useLocation } from 'react-router-dom';
import { Shield, Home, Search, Settings, LogOut } from 'lucide-react';
import { useAuth } from '../../auth/auth-context';
import { cn } from '../../lib/utils';

export function Sidebar() {
  const { user, logout } = useAuth();
  const location = useLocation();

  const navItems = [
    {
      label: 'Dashboard',
      path: '/',
      icon: Home,
      roles: ['investigator', 'analyst', 'administrator'],
      exact: true,
    },
    {
      label: 'Investigations',
      path: '/investigations',
      icon: Search,
      roles: ['investigator', 'analyst', 'administrator'],
      exact: false,
    },
  ];

  // Role-aware navigation filter
  const visibleItems = navItems.filter((item) =>
    !user || item.roles.includes(user.role)
  );

  return (
    <aside className="w-64 border-r border-border-subtle bg-surface flex flex-col h-full flex-shrink-0">
      {/* Logo */}
      <div className="h-14 flex items-center px-6 border-b border-border-subtle flex-shrink-0">
        <Shield className="h-5 w-5 text-accent mr-2" aria-hidden="true" />
        <span className="font-semibold text-primary tracking-tight">NetSleuth AI</span>
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 flex flex-col gap-0.5 overflow-y-auto px-3" aria-label="Main navigation">
        {visibleItems.map((item) => {
          const isActive = item.exact
            ? location.pathname === item.path
            : location.pathname === item.path ||
              location.pathname.startsWith(item.path + '/');
          const Icon = item.icon;
          return (
            <Link
              key={item.path}
              to={item.path}
              aria-current={isActive ? 'page' : undefined}
              className={cn(
                'flex items-center px-3 py-2 text-sm rounded-md transition-colors',
                isActive
                  ? 'bg-surface-elevated text-primary font-medium'
                  : 'text-secondary hover:bg-surface-elevated hover:text-primary'
              )}
            >
              <Icon
                className={cn('h-4 w-4 mr-3 flex-shrink-0', isActive ? 'text-accent' : 'text-muted')}
                aria-hidden="true"
              />
              <span className="truncate">{item.label}</span>
            </Link>
          );
        })}

        {/* Admin section */}
        {user?.role === 'administrator' && (
          <>
            <div className="my-2 border-t border-border-subtle mx-0" aria-hidden="true" />
            <Link
              to="/admin"
              aria-current={location.pathname.startsWith('/admin') ? 'page' : undefined}
              className={cn(
                'flex items-center px-3 py-2 text-sm rounded-md transition-colors',
                location.pathname.startsWith('/admin')
                  ? 'bg-surface-elevated text-primary font-medium'
                  : 'text-secondary hover:bg-surface-elevated hover:text-primary'
              )}
            >
              <Settings
                className={cn(
                  'h-4 w-4 mr-3',
                  location.pathname.startsWith('/admin') ? 'text-accent' : 'text-muted'
                )}
                aria-hidden="true"
              />
              Settings
            </Link>
          </>
        )}
      </nav>

      {/* User Footer */}
      <div className="p-4 border-t border-border-subtle flex-shrink-0">
        <div className="flex items-center mb-3 px-1">
          <div
            className="h-8 w-8 rounded-full bg-surface-elevated flex items-center justify-center border border-border-subtle mr-3 flex-shrink-0"
            aria-hidden="true"
          >
            <span className="text-xs font-medium text-primary">
              {user?.username?.charAt(0).toUpperCase() ?? 'U'}
            </span>
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-sm font-medium text-primary leading-none mb-1 truncate">
              {user?.username}
            </span>
            <span className="text-xs text-muted leading-none capitalize">{user?.role}</span>
          </div>
        </div>
        <button
          onClick={logout}
          className="flex w-full items-center px-2 py-1.5 text-sm text-secondary hover:text-primary transition-colors rounded-md hover:bg-surface-elevated focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          aria-label="Sign out"
        >
          <LogOut className="h-4 w-4 mr-3 text-muted flex-shrink-0" aria-hidden="true" />
          Sign out
        </button>
      </div>
    </aside>
  );
}
