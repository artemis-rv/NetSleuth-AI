import { Link, useLocation, matchPath, useNavigate } from 'react-router-dom';
import {
  Shield, Home, Search, Settings, LogOut, Terminal,
  LayoutDashboard, AlertTriangle, Activity, Clock, Share2,
  FolderOpen, FileText, Sparkles, ChevronLeft
} from 'lucide-react';
import { useAuth } from '../../auth/auth-context';
import { cn } from '../../lib/utils';
import { useCaseQuery, useCasesQuery } from '../../features/cases/hooks';
import { CaseStatusBadge } from '../../features/cases/components/CaseBadge';

const TABS = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: AlertTriangle },
  { id: 'network', label: 'Network', icon: Activity },
  { id: 'timeline', label: 'Timeline', icon: Clock },
  { id: 'graph', label: 'Graph', icon: Share2 },
  { id: 'mitre', label: 'MITRE', icon: Shield },
  { id: 'evidence', label: 'Evidence', icon: FolderOpen },
  { id: 'reports', label: 'Reports', icon: FileText },
  { id: 'copilot', label: 'AI Copilot', icon: Sparkles },
] as const;

export function Sidebar() {
  const { user, logout } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();

  // Check if we are inside a case
  const match = matchPath({ path: '/investigations/:caseId/:tab?' }, location.pathname);
  const isNew = location.pathname === '/investigations/new';
  const caseId = isNew ? null : match?.params.caseId;
  const activeTab = match?.params.tab || 'overview';

  // We only fetch if caseId exists
  const { data: caseData } = useCaseQuery(caseId ?? '');

  // Fetch recent cases for the sidebar
  const { data: recentCasesData } = useCasesQuery({ sort_by: 'updated_at', page_size: 5 });
  const recentCases = recentCasesData?.items || [];

  const mainItems = [
    { label: 'Dashboard', path: '/', icon: Home, roles: ['investigator', 'analyst', 'administrator'], exact: true },
    { label: 'Investigations', path: '/investigations', icon: Search, roles: ['investigator', 'analyst', 'administrator'], exact: false },
  ];

  const visibleMainItems = mainItems.filter((item) => !user || item.roles.includes(user.role));

  const renderNavItem = (item: any) => {
    const isActive = item.exact
      ? location.pathname === item.path
      : location.pathname === item.path || (location.pathname.startsWith(item.path + '/') && !caseId);
    const Icon = item.icon;

    return (
      <Link
        key={item.path}
        to={item.path}
        aria-current={isActive ? 'page' : undefined}
        className={cn(
          'group flex items-center px-3 py-2 text-sm rounded-md transition-all duration-200 border-l-2',
          isActive
            ? 'border-accent bg-surface-elevated/50 text-primary font-medium shadow-[inset_0_1px_0_0_rgba(255,255,255,0.05)]'
            : 'border-transparent text-secondary hover:bg-surface-elevated/60 hover:text-primary'
        )}
      >
        <div className="flex items-center flex-1 transition-transform duration-200 group-hover:translate-x-1 min-w-0">
          <Icon className={cn('h-4 w-4 mr-3 flex-shrink-0 transition-colors', isActive ? 'text-accent drop-shadow-[0_0_8px_rgba(59,130,246,0.5)]' : 'text-muted group-hover:text-primary')} aria-hidden="true" />
          <span className="truncate flex-1">{item.label}</span>
        </div>
      </Link>
    );
  };

  const renderCaseNavigation = () => (
    <>
      <div className="px-3 mb-4 mt-2">
        <button
          onClick={() => navigate('/investigations')}
          className="flex items-center text-xs text-muted hover:text-primary transition-colors group"
        >
          <ChevronLeft className="h-3 w-3 mr-1 group-hover:-translate-x-0.5 transition-transform" />
          Back to Workspace
        </button>
      </div>

      {caseData && (
        <div className="px-4 mb-6">
          <div className="flex items-center mb-2">
            <CaseStatusBadge status={caseData.status} />
          </div>
          <h2 className="text-sm font-semibold text-primary leading-tight line-clamp-2 break-all" title={caseData.title}>
            {caseData.title}
          </h2>
        </div>
      )}

      <div className="mb-6">
        <h3 className="px-3 text-xs font-semibold text-muted tracking-wider uppercase mb-2">Investigation</h3>
        <div className="flex flex-col gap-0.5 px-3">
          {TABS.map(tab => {
            const isActive = activeTab === tab.id;
            const Icon = tab.icon;
            return (
              <Link
                key={tab.id}
                to={`/investigations/${caseId}/${tab.id}`}
                className={cn(
                  'group flex items-center px-3 py-2 text-sm rounded-md transition-all duration-200 border-l-2',
                  isActive
                    ? 'border-accent bg-surface-elevated/50 text-primary font-medium shadow-[inset_0_1px_0_0_rgba(255,255,255,0.05)]'
                    : 'border-transparent text-secondary hover:bg-surface-elevated/60 hover:text-primary'
                )}
              >
                <div className="flex items-center flex-1 transition-transform duration-200 group-hover:translate-x-1 min-w-0">
                  <Icon className={cn('h-4 w-4 mr-3 flex-shrink-0 transition-colors', isActive ? 'text-accent drop-shadow-[0_0_8px_rgba(59,130,246,0.5)]' : 'text-muted group-hover:text-primary')} aria-hidden="true" />
                  <span className="truncate flex-1">{tab.label}</span>
                </div>
              </Link>
            );
          })}
        </div>
      </div>
    </>
  );

  const renderGlobalNavigation = () => (
    <>
      <div className="mb-6">
        <h3 className="px-3 text-xs font-semibold text-muted tracking-wider uppercase mb-2">Main Menu</h3>
        <div className="flex flex-col gap-0.5">
          {visibleMainItems.map(renderNavItem)}
        </div>
      </div>

      <div className="mb-6">
        <h3 className="px-3 text-xs font-semibold text-muted tracking-wider uppercase mb-2">Recent Cases</h3>
        <div className="flex flex-col gap-1 px-1">
          {recentCases.map(caseItem => (
            <Link key={caseItem.case_id} to={`/investigations/${caseItem.case_id}`} className="group flex items-center px-2 py-1.5 rounded-md hover:bg-surface-elevated transition-colors duration-200">
              <div className="flex items-center flex-1 transition-transform duration-200 group-hover:translate-x-1 min-w-0">
                <div className={cn(
                  "w-1.5 h-1.5 rounded-full mr-3 flex-shrink-0 shadow-sm",
                  caseItem.status === 'critical' ? 'bg-error shadow-error/50' : 'bg-success shadow-success/50'
                )} />
                <span className="text-xs text-secondary group-hover:text-primary truncate transition-colors">{caseItem.title}</span>
              </div>
            </Link>
          ))}
        </div>
      </div>

      <div className="flex-1" />

      {user?.role === 'administrator' && (
        <div className="mt-auto">
          <h3 className="px-3 text-xs font-semibold text-muted tracking-wider uppercase mb-2 mt-4 border-t border-border-subtle pt-4">System</h3>
          <Link
            to="/admin"
            className={cn(
              'group flex items-center px-3 py-2 text-sm rounded-md transition-all duration-200 border-l-2',
              location.pathname.startsWith('/admin')
                ? 'border-accent bg-surface-elevated/50 text-primary font-medium shadow-[inset_0_1px_0_0_rgba(255,255,255,0.05)]'
                : 'border-transparent text-secondary hover:bg-surface-elevated/60 hover:text-primary'
            )}
          >
            <div className="flex items-center flex-1 transition-transform duration-200 group-hover:translate-x-1 min-w-0">
              <Settings className={cn('h-4 w-4 mr-3 transition-colors', location.pathname.startsWith('/admin') ? 'text-accent drop-shadow-[0_0_8px_rgba(59,130,246,0.5)]' : 'text-muted group-hover:text-primary')} />
              Settings
            </div>
          </Link>
        </div>
      )}
    </>
  );

  return (
    <aside className="w-64 border-r border-border-subtle bg-[#0B0E14] flex flex-col h-full flex-shrink-0 z-50">
      <div className="h-20 flex items-center justify-start px-5 border-b border-border-subtle flex-shrink-0 bg-surface/50">
        <img src="/logo.png" alt="NetSleuth AI Logo" className="w-60 h-auto object-contain drop-shadow-[0_0_8px_rgba(59,130,246,0.3)]" />
      </div>

      {!caseId && (
        <div className="px-4 py-4 flex-shrink-0">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted" />
            <input
              type="text"
              placeholder="Search cases, IPs..."
              className="w-full bg-surface-elevated border border-border-subtle rounded-md pl-9 pr-3 py-1.5 text-sm text-primary placeholder:text-muted focus:outline-none focus:ring-1 focus:ring-accent/50 focus:border-accent/50 transition-all"
            />
          </div>
        </div>
      )}
      {caseId && <div className="h-4" />}

      <nav className="flex-1 pb-4 flex flex-col overflow-y-auto px-1 custom-scrollbar" aria-label="Main navigation">
        {caseId ? renderCaseNavigation() : renderGlobalNavigation()}
      </nav>

      <div className="px-4 py-3 border-t border-border-subtle bg-surface-elevated/20">
        <div className="flex items-center justify-between">
          <div className="flex items-center text-xs text-secondary">
            <Terminal className="h-3.5 w-3.5 mr-2 text-muted" />
            <span>M3 Engine</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="text-[10px] font-medium text-success uppercase tracking-wider">Active</span>
            <div className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2 w-2 bg-success"></span>
            </div>
          </div>
        </div>
      </div>

      <div className="p-4 border-t border-border-subtle flex-shrink-0 bg-surface/50">
        <div className="flex items-center mb-3 px-1">
          <div className="h-8 w-8 rounded-full bg-surface-elevated flex items-center justify-center border border-border-subtle mr-3 flex-shrink-0">
            <span className="text-xs font-medium text-primary">{user?.username?.charAt(0).toUpperCase() ?? 'U'}</span>
          </div>
          <div className="flex flex-col min-w-0">
            <span className="text-sm font-medium text-primary leading-none mb-1 truncate">{user?.username}</span>
            <span className="text-xs text-muted leading-none capitalize">{user?.role}</span>
          </div>
        </div>
        <button
          onClick={logout}
          className="flex w-full items-center px-2 py-1.5 text-sm text-secondary hover:text-primary transition-colors rounded-md hover:bg-surface-elevated"
        >
          <LogOut className="h-4 w-4 mr-3 text-muted flex-shrink-0" />
          Sign out
        </button>
      </div>
    </aside>
  );
}
