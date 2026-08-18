import type { FindingListItem } from '../types';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
};

const DECISION_STYLES: Record<string, string> = {
  confirmed_tp: 'bg-red-500/10 text-red-400',
  confirmed_fp: 'bg-slate-500/10 text-slate-400',
  under_review: 'bg-yellow-500/10 text-yellow-400',
  pending: 'bg-slate-500/10 text-slate-400',
};

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    hour12: false,
  });
}

function RiskBar({ score }: { score: number | null }) {
  if (score === null) return <span className="text-xs text-muted">—</span>;
  const pct = Math.min(100, Math.max(0, score * 100));
  const color = score >= 0.8 ? 'bg-red-500' : score >= 0.6 ? 'bg-orange-400' : score >= 0.4 ? 'bg-yellow-400' : 'bg-blue-400';
  return (
    <div className="flex items-center gap-1.5">
      <div className="w-16 h-1.5 rounded-full bg-surface-elevated overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs text-secondary tabular-nums">{score.toFixed(2)}</span>
    </div>
  );
}

interface FindingRowProps {
  finding: FindingListItem;
  onClick: (finding: FindingListItem) => void;
}

export function FindingRow({ finding, onClick }: FindingRowProps) {
  const sevStyle = SEVERITY_STYLES[finding.severity?.toLowerCase()] ?? SEVERITY_STYLES.info;
  const decStyle = DECISION_STYLES[finding.decision_state?.toLowerCase()] ?? DECISION_STYLES.pending;

  return (
    <tr
      className="border-b border-border-subtle hover:bg-surface-elevated/50 cursor-pointer transition-colors group"
      onClick={() => onClick(finding)}
      role="button"
      aria-label={`View finding: ${finding.activity}`}
    >
      {/* Severity */}
      <td className="px-4 py-2.5 whitespace-nowrap">
        <span className={`inline-flex items-center rounded border px-2 py-0.5 text-xs font-semibold uppercase tracking-wide ${sevStyle}`}>
          {finding.severity}
        </span>
      </td>

      {/* Activity */}
      <td className="px-4 py-2.5 max-w-xs">
        <span className="text-sm text-primary font-mono truncate block">
          {finding.activity.replace(/_/g, ' ')}
        </span>
      </td>

      {/* Risk Score */}
      <td className="px-4 py-2.5 whitespace-nowrap">
        <RiskBar score={finding.risk_score} />
      </td>

      {/* Decision State */}
      <td className="px-4 py-2.5 whitespace-nowrap">
        <span className={`inline-flex items-center rounded px-2 py-0.5 text-xs font-medium ${decStyle}`}>
          {finding.decision_state.replace(/_/g, ' ')}
        </span>
      </td>

      {/* Detection Method */}
      <td className="px-4 py-2.5 hidden md:table-cell whitespace-nowrap">
        <span className="text-xs text-muted font-mono">{finding.detection_method}</span>
      </td>

      {/* Detected At */}
      <td className="px-4 py-2.5 whitespace-nowrap text-right">
        <span className="text-xs text-muted tabular-nums">{formatDate(finding.detected_at)}</span>
      </td>
    </tr>
  );
}
