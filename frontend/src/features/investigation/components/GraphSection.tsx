import { AlertCircle, ArrowRight, Cpu } from 'lucide-react';
import { useGraphQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';

const ENTITY_TYPE_STYLES: Record<string, string> = {
  ip_address: 'border-blue-500/40 bg-blue-500/10',
  domain: 'border-purple-500/40 bg-purple-500/10',
  host: 'border-teal-500/40 bg-teal-500/10',
  user: 'border-green-500/40 bg-green-500/10',
  file: 'border-yellow-500/40 bg-yellow-500/10',
  process: 'border-orange-500/40 bg-orange-500/10',
};

function RiskDot({ score }: { score: number | null }) {
  if (score === null) return null;
  const color = score >= 0.8 ? 'bg-red-500' : score >= 0.6 ? 'bg-orange-400' : score >= 0.4 ? 'bg-yellow-400' : 'bg-slate-400';
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full ${color} flex-shrink-0`}
      title={`Risk: ${score.toFixed(2)}`}
    />
  );
}

interface GraphSectionProps {
  caseId: string;
}

export function GraphSection({ caseId }: GraphSectionProps) {
  const { data, isLoading, isError, error } = useGraphQuery(caseId);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Spinner size={28} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
        <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
        Failed to load attack graph. {(error as Error)?.message}
      </div>
    );
  }

  if (!data || data.nodes.length === 0) {
    return (
      <EmptyState
        title="No Graph Data"
        description="No entity graph has been built for this investigation yet."
      />
    );
  }

  // Build a name lookup from entity_id → name
  const nodeMap = new Map(data.nodes.map((n) => [n.entity_id, n]));

  return (
    <div className="space-y-6">
      {/* Summary */}
      <div className="flex items-center gap-4 text-xs text-muted">
        <span className="flex items-center gap-1.5">
          <Cpu className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
          {data.nodes.length} node{data.nodes.length !== 1 ? 's' : ''}
        </span>
        <span>·</span>
        <span>{data.edges.length} edge{data.edges.length !== 1 ? 's' : ''}</span>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Node list */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-muted border-b border-border-subtle pb-1">
            Nodes
          </h3>
          <div className="space-y-1.5 max-h-96 overflow-y-auto pr-1">
            {data.nodes.map((node) => {
              const typeStyle = ENTITY_TYPE_STYLES[node.entity_type?.toLowerCase()] ?? 'border-slate-500/40 bg-slate-500/10';
              return (
                <div
                  key={node.entity_id}
                  className={`flex items-center gap-2.5 px-3 py-2 rounded border ${typeStyle}`}
                >
                  <RiskDot score={node.risk_score} />
                  <div className="flex-1 min-w-0">
                    <p className="text-xs font-mono text-primary truncate">{node.name}</p>
                    <p className="text-[10px] text-muted">{node.entity_type.replace(/_/g, ' ')}</p>
                  </div>
                  {node.risk_score !== null && (
                    <span className="text-[10px] text-muted tabular-nums flex-shrink-0">
                      {node.risk_score.toFixed(2)}
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>

        {/* Edge list */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-muted border-b border-border-subtle pb-1">
            Edges
          </h3>
          <div className="space-y-1.5 max-h-96 overflow-y-auto pr-1">
            {data.edges.map((edge) => {
              const src = nodeMap.get(edge.source_entity_id);
              const tgt = nodeMap.get(edge.target_entity_id);
              return (
                <div
                  key={edge.relationship_id}
                  className="flex items-center gap-2 px-3 py-2 rounded border border-border-subtle hover:bg-surface-elevated/40 transition-colors"
                >
                  <span className="text-[11px] text-primary font-mono truncate max-w-[100px]" title={src?.name}>
                    {src?.name ?? edge.source_entity_id.slice(0, 8)}
                  </span>
                  <div className="flex items-center gap-1 flex-shrink-0">
                    <ArrowRight className="h-3 w-3 text-muted" aria-hidden="true" />
                    <span className="text-[10px] text-accent">{edge.relationship_type.replace(/_/g, ' ')}</span>
                    <ArrowRight className="h-3 w-3 text-muted" aria-hidden="true" />
                  </div>
                  <span className="text-[11px] text-primary font-mono truncate max-w-[100px]" title={tgt?.name}>
                    {tgt?.name ?? edge.target_entity_id.slice(0, 8)}
                  </span>
                  {edge.confidence !== null && (
                    <span className="ml-auto text-[10px] text-muted tabular-nums flex-shrink-0">
                      {Math.round(edge.confidence * 100)}%
                    </span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
