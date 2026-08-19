import type { FindingListItem } from '../types';

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-400 border-red-500/20',
  high: 'bg-orange-500/10 text-orange-400 border-orange-500/20',
  medium: 'bg-amber-500/10 text-amber-400 border-amber-500/20',
  low: 'bg-blue-500/10 text-blue-400 border-blue-500/20',
  info: 'bg-slate-500/10 text-slate-400 border-slate-500/20',
};

const DECISION_STYLES: Record<string, string> = {
  confirmed_tp: 'bg-red-500/10 text-red-400 border border-red-500/20',
  confirmed_fp: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',
  under_review: 'bg-amber-500/10 text-amber-400 border border-amber-500/20',
  pending: 'bg-slate-500/10 text-slate-400 border border-slate-500/20',
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
  const color = score >= 0.8 ? 'bg-red-500' : score >= 0.6 ? 'bg-orange-500' : score >= 0.4 ? 'bg-amber-400' : 'bg-blue-500';
  return (
    <div className="flex items-center gap-2.5">
      <div className="w-20 h-1.5 rounded-sm bg-surface border border-border-subtle overflow-hidden">
        <div className={`h-full rounded-sm ${color}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[11px] text-secondary tabular-nums font-mono w-7">{score.toFixed(2)}</span>
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
      className="border-b border-border-subtle hover:bg-surface-elevated/70 cursor-pointer transition-colors group focus-within:bg-surface-elevated outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-accent"
      onClick={() => onClick(finding)}
      onKeyDown={(e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onClick(finding);
        }
      }}
      tabIndex={0}
      role="button"
      aria-label={`View finding: ${finding.activity}`}
    >
      {/* Severity */}
      <td className="px-4 py-2.5 whitespace-nowrap align-middle">
        <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-widest ${sevStyle}`}>
          {finding.severity}
        </span>
      </td>

      {/* Activity */}
      <td className="px-4 py-2.5 max-w-xs align-middle">
        <span className="text-[13px] text-primary font-mono truncate block font-medium group-hover:text-accent transition-colors">
          {finding.activity.replace(/_/g, ' ')}
        </span>
      </td>

      {/* Risk Score */}
      <td className="px-4 py-2.5 whitespace-nowrap align-middle">
        <RiskBar score={finding.risk_score} />
      </td>

      {/* Decision State */}
      <td className="px-4 py-2.5 whitespace-nowrap align-middle">
        <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${decStyle}`}>
          {finding.decision_state.replace(/_/g, ' ')}
        </span>
      </td>

      {/* Detection Method */}
      <td className="px-4 py-2.5 hidden md:table-cell whitespace-nowrap align-middle">
        <span className="text-[11px] text-muted font-mono">{finding.detection_method}</span>
      </td>

      {/* Detected At */}
      <td className="px-4 py-2.5 whitespace-nowrap text-right align-middle">
        <span className="text-[11px] text-muted tabular-nums font-mono">{formatDate(finding.detected_at)}</span>
      </td>
    </tr>
  );
}
