import { Link, useLocation } from 'react-router-dom';
import { Shield, Home, Search, Activity, Network, Box, Database, FileText, Settings, LogOut } from 'lucide-react';
import { useAuth } from '../../auth/auth-context';
import { cn } from '../../lib/utils';

export function Sidebar() {
  const { user, logout } = useAuth();
  const location = useLocation();

  const navItems = [
    { label: 'Dashboard', path: '/', icon: Home, roles: ['investigator', 'analyst', 'administrator'] },
    { label: 'Cases', path: '/cases', icon: Box, roles: ['investigator', 'analyst', 'administrator'] },
    { label: 'Investigation', path: '/investigation', icon: Search, roles: ['investigator', 'administrator'] },
    { label: 'Network', path: '/network', icon: Network, roles: ['investigator', 'analyst', 'administrator'] },
    { label: 'Timeline', path: '/timeline', icon: Activity, roles: ['investigator', 'analyst', 'administrator'] },
    { label: 'Evidence', path: '/evidence', icon: Database, roles: ['investigator', 'administrator'] },
    { label: 'Reports', path: '/reports', icon: FileText, roles: ['investigator', 'analyst', 'administrator'] },
  ];

  // Role-aware navigation filter
  const visibleItems = navItems.filter(item => 
    !user || item.roles.includes(user.role)
  );

  return (
    <aside className="w-64 border-r border-border-subtle bg-surface flex flex-col h-full flex-shrink-0">
      <div className="h-14 flex items-center px-6 border-b border-border-subtle">
        <Shield className="h-5 w-5 text-accent mr-2" />
        <span className="font-semibold text-primary tracking-tight">NetSleuth AI</span>
      </div>
      
      <nav className="flex-1 py-4 flex flex-col gap-1 overflow-y-auto px-3">
        {visibleItems.map(item => {
          const isActive = location.pathname === item.path || (item.path !== '/' && location.pathname.startsWith(item.path));
          const Icon = item.icon;
          return (
            <Link
              key={item.path}
              to={item.path}
              className={cn(
                "flex items-center px-3 py-2 text-sm rounded-md transition-colors",
                isActive 
                  ? "bg-surface-elevated text-primary font-medium" 
                  : "text-secondary hover:bg-surface-elevated hover:text-primary"
              )}
            >
              <Icon className={cn("h-4 w-4 mr-3", isActive ? "text-accent" : "text-muted")} />
              {item.label}
            </Link>
          );
        })}

        {user?.role === 'administrator' && (
          <>
            <div className="my-2 border-t border-border-subtle mx-3" />
            <Link
              to="/admin"
              className={cn(
                "flex items-center px-3 py-2 text-sm rounded-md transition-colors",
                location.pathname.startsWith('/admin')
                  ? "bg-surface-elevated text-primary font-medium" 
                  : "text-secondary hover:bg-surface-elevated hover:text-primary"
              )}
            >
              <Settings className="h-4 w-4 mr-3 text-muted" />
              Settings
            </Link>
          </>
        )}
      </nav>

      <div className="p-4 border-t border-border-subtle">
        <div className="flex items-center mb-4 px-2">
          <div className="h-8 w-8 rounded-full bg-surface-elevated flex items-center justify-center border border-border-subtle mr-3">
            <span className="text-xs font-medium text-primary">
              {user?.username?.charAt(0).toUpperCase() || 'U'}
            </span>
          </div>
          <div className="flex flex-col">
            <span className="text-sm font-medium text-primary leading-none mb-1">{user?.username}</span>
            <span className="text-xs text-muted leading-none capitalize">{user?.role}</span>
          </div>
        </div>
        <button
          onClick={logout}
          className="flex w-full items-center px-2 py-1.5 text-sm text-secondary hover:text-primary transition-colors rounded-md hover:bg-surface-elevated"
        >
          <LogOut className="h-4 w-4 mr-3 text-muted" />
          Sign out
        </button>
      </div>
    </aside>
  );
}
