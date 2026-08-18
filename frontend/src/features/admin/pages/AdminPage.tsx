import { Settings, Server, Shield, CheckCircle2, AlertTriangle, Lock } from 'lucide-react';
import { useSystemStatusQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { Card, CardHeader, CardTitle, CardContent } from '../../../components/ui/Card';

export function AdminPage() {
  const { data, isLoading, isError, error, refetch } = useSystemStatusQuery();

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-primary flex items-center gap-2">
            <Settings className="h-5 w-5 text-accent" />
            System Administration
          </h1>
          <p className="text-xs text-muted">Platform status, service health, and security controls</p>
        </div>
        <button
          onClick={() => refetch()}
          className="px-3 py-1.5 text-xs text-secondary hover:text-primary border border-border-subtle rounded hover:bg-surface-elevated transition-colors"
        >
          Refresh Status
        </button>
      </div>

      {isLoading && (
        <div className="flex items-center justify-center py-16">
          <Spinner size={32} />
        </div>
      )}

      {isError && (
        <div className="p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle className="h-4 w-4 flex-shrink-0" />
          Failed to fetch system status: {(error as Error)?.message}
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {/* Status Overview Card */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Server className="h-4 w-4 text-accent" />
                Operational Status
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3 pt-0">
              <div className="flex justify-between items-center py-1 border-b border-border-subtle">
                <span className="text-xs text-muted">System State:</span>
                <span className="inline-flex items-center gap-1 text-xs font-semibold text-green-400 bg-green-500/10 px-2 py-0.5 rounded border border-green-500/20">
                  <CheckCircle2 className="h-3 w-3" />
                  {data.status || 'OPERATIONAL'}
                </span>
              </div>
              {data.environment && (
                <div className="flex justify-between items-center py-1 border-b border-border-subtle">
                  <span className="text-xs text-muted">Environment:</span>
                  <span className="text-xs font-mono text-primary uppercase">{data.environment}</span>
                </div>
              )}
              {data.version && (
                <div className="flex justify-between items-center py-1 border-b border-border-subtle">
                  <span className="text-xs text-muted">API Contract Version:</span>
                  <span className="text-xs font-mono text-secondary">v{data.version}</span>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Role Policy Summary Card */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-accent" />
                Frontend Role Access Policy
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 pt-0 text-xs">
              <div className="p-2.5 rounded bg-surface-elevated/40 border border-border-subtle space-y-1">
                <span className="font-semibold text-primary block">Administrator:</span>
                <span className="text-muted leading-relaxed">Full system access, operational status, case management, and system administration.</span>
              </div>
              <div className="p-2.5 rounded bg-surface-elevated/40 border border-border-subtle space-y-1">
                <span className="font-semibold text-primary block">Investigator:</span>
                <span className="text-muted leading-relaxed">Case creation, evidence acquisition, analysis triggering, findings, network analysis, timeline, attack chain, and report review.</span>
              </div>
              <div className="p-2.5 rounded bg-surface-elevated/40 border border-border-subtle space-y-1">
                <span className="font-semibold text-primary block">Analyst:</span>
                <span className="text-muted leading-relaxed">ReadOnly / Review access to assigned cases, findings, network flows, timeline, graph, and evidence. Case creation and admin controls are restricted.</span>
              </div>
            </CardContent>
          </Card>

          {/* Deferred API Boundaries Notice */}
          <div className="md:col-span-2 p-4 rounded border border-border-subtle bg-surface-elevated/30 text-xs text-muted space-y-2">
            <div className="flex items-center gap-2 font-semibold text-primary">
              <Lock className="h-4 w-4 text-accent" />
              Administrative Endpoint Boundaries (API Contract Audit)
            </div>
            <p className="leading-relaxed">
              Per the frozen OpenAPI v1 contract (<code className="font-mono bg-black/20 px-1 py-0.5 rounded">docs/api/openapi-v1.json</code>), system administration exposes <code className="font-mono bg-black/20 px-1 py-0.5 rounded">GET /api/v1/admin/system-status</code>. User management, case access control, audit logging, and model registry endpoints are managed at the infrastructure level and are deferred for future API expansions.
            </p>
          </div>
        </div>
      )}
    </div>
  );
}
