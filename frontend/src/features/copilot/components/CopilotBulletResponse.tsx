/**
 * CopilotBulletResponse.tsx
 *
 * Pure presentational component.
 * Renders a structured Copilot answer as clean bullet cards.
 * NEVER renders raw JSON, question fields, or prose paragraphs.
 */

import React from 'react';

export interface CopilotPoint {
  title: string;
  explanation: string;
  evidence_ids?: string[];
  finding_ids?: string[];
  technique_ids?: string[];
  status?: string;
  confidence?: number;
}

export interface CopilotResponseShape {
  heading?: string;
  summary?: string;
  points: CopilotPoint[];
  confirmed?: string[];
  unconfirmed?: string[];
  recommendations?: string[];
  limitations?: string[];
}

// ── inline rich text (bold + code) ──────────────────────────────────────────
function renderInline(text: string): React.ReactNode[] {
  const regex = /(\*\*.*?\*\*|`[^`]+`)/g;
  const tokens = text.split(regex);
  return tokens.map((tok, i) => {
    if (tok.startsWith('**') && tok.endsWith('**')) {
      return <strong key={i} className="font-semibold text-primary">{tok.slice(2, -2)}</strong>;
    }
    if (tok.startsWith('`') && tok.endsWith('`')) {
      const val = tok.slice(1, -1);
      const isId =
        /^[a-fA-F0-9\-]{8,36}$/.test(val) ||
        /^ev-/i.test(val) ||
        /^t\d+/i.test(val) ||
        /^f-/i.test(val);
      return (
        <code
          key={i}
          className={`px-1 py-0.5 rounded font-mono text-[11px] select-all ${
            isId
              ? 'bg-accent/10 border border-accent/25 text-accent'
              : 'bg-surface-elevated border border-border-subtle text-secondary'
          }`}
        >
          {val}
        </code>
      );
    }
    return tok;
  });
}

// ── status badge colour ──────────────────────────────────────────────────────
function statusClass(status: string): string {
  switch (status.toUpperCase()) {
    case 'SUPPORTED':
    case 'OBSERVED':
      return 'bg-green-500/10 text-green-500 border-green-500/25';
    case 'PARTIAL':
    case 'INFERRED':
      return 'bg-blue-500/10 text-blue-500 border-blue-500/25';
    case 'UNCONFIRMED':
    case 'POTENTIAL':
      return 'bg-yellow-500/10 text-yellow-500 border-yellow-500/25';
    default:
      return 'bg-surface-elevated text-secondary border-border-subtle';
  }
}

// ── risk badge colour ────────────────────────────────────────────────────────
function riskBadge(risk: string): React.ReactNode {
  const riskUpper = risk.toUpperCase();
  const cls =
    riskUpper === 'CRITICAL'
      ? 'bg-red-600/10 text-red-600 border-red-600/25'
      : riskUpper === 'HIGH'
      ? 'bg-red-500/10 text-red-500 border-red-500/25'
      : riskUpper === 'MEDIUM'
      ? 'bg-orange-500/10 text-orange-500 border-orange-500/25'
      : 'bg-slate-500/10 text-slate-400 border-slate-500/25';
  return (
    <span key="risk" className={`px-1.5 py-0.5 text-[9px] font-bold rounded border uppercase ${cls}`}>
      {riskUpper}
    </span>
  );
}

// ── single bullet card ───────────────────────────────────────────────────────
function BulletCard({ point, index }: { point: CopilotPoint; index: number }) {
  const hasExplanation = point.explanation && point.explanation.trim().length > 0;
  const hasMeta =
    point.status ||
    (point.confidence !== undefined && point.confidence !== null) ||
    (point.technique_ids && point.technique_ids.length > 0) ||
    (point.finding_ids && point.finding_ids.length > 0) ||
    (point.evidence_ids && point.evidence_ids.length > 0);

  // Detect inline risk label like "Risk: HIGH" in title and strip it out
  const riskMatch = point.title.match(/\bRisk:\s*(CRITICAL|HIGH|MEDIUM|LOW)\b/i);
  const cleanTitle = riskMatch
    ? point.title.replace(riskMatch[0], '').trim()
    : point.title;

  return (
    <div
      className="flex gap-3 p-3 rounded-lg border border-border-subtle bg-surface-elevated hover:border-accent/30 transition-colors select-text"
      data-testid={`bullet-card-${index}`}
    >
      {/* Bullet icon */}
      <span className="text-accent mt-0.5 text-base leading-none select-none flex-shrink-0" aria-hidden="true">•</span>

      <div className="flex-1 min-w-0 space-y-1.5">
        {/* Title row */}
        <div className="flex items-start gap-2 flex-wrap">
          <span className="text-xs font-bold text-primary leading-snug">
            {renderInline(cleanTitle)}
          </span>
          {riskMatch && riskBadge(riskMatch[1])}
        </div>

        {/* Explanation */}
        {hasExplanation && (
          <div className="text-xs text-secondary leading-relaxed">
            {renderInline(point.explanation)}
          </div>
        )}

        {/* Metadata badges */}
        {hasMeta && (
          <div className="flex flex-wrap gap-1.5 pt-1">
            {point.status && (
              <span
                className={`px-1.5 py-0.5 text-[9px] font-bold rounded border uppercase ${statusClass(point.status)}`}
                data-testid="status-badge"
              >
                {point.status}
              </span>
            )}
            {point.confidence !== undefined && point.confidence !== null && (
              <span
                className="px-1.5 py-0.5 text-[9px] font-semibold rounded bg-surface-elevated border border-border-subtle text-secondary font-mono"
                data-testid="confidence-badge"
              >
                {Math.round(point.confidence <= 1 ? point.confidence * 100 : point.confidence)}%
              </span>
            )}
            {point.technique_ids?.map(t => (
              <code
                key={t}
                className="px-1.5 py-0.5 rounded bg-accent/10 border border-accent/25 text-accent select-all text-[9px] font-semibold"
                data-testid={`mitre-badge-${t}`}
              >
                {t}
              </code>
            ))}
            {point.finding_ids?.map(f => (
              <code
                key={f}
                className="px-1.5 py-0.5 rounded bg-violet-500/10 border border-violet-500/25 text-violet-400 select-all text-[9px] font-semibold"
                data-testid={`finding-badge-${f}`}
              >
                {f}
              </code>
            ))}
            {point.evidence_ids?.map(ev => (
              <code
                key={ev}
                className="px-1.5 py-0.5 rounded bg-sky-500/10 border border-sky-500/25 text-sky-400 select-all text-[9px] font-semibold"
                data-testid={`evidence-badge-${ev}`}
              >
                {ev}
              </code>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

// ── section sublist (confirmed / unconfirmed / limitations) ──────────────────
function SubList({
  items,
  icon,
  iconClass,
  label,
}: {
  items: string[];
  icon: string;
  iconClass: string;
  label: string;
}) {
  if (!items || items.length === 0) return null;
  return (
    <div className="space-y-1.5 pt-1 select-text">
      <h4 className="text-[10px] font-bold uppercase tracking-wider text-muted select-none">
        {label}
      </h4>
      <ul className="space-y-1 pl-0">
        {items.map((item, idx) => (
          <li key={idx} className="text-xs text-secondary flex items-start gap-1.5">
            <span className={`${iconClass} font-bold select-none`}>{icon}</span>
            <span className="flex-1 leading-relaxed">{renderInline(item)}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

// ── main export ──────────────────────────────────────────────────────────────
export function CopilotBulletResponse({ response }: { response: CopilotResponseShape }) {
  const {
    heading,
    summary,
    points = [],
    confirmed = [],
    unconfirmed = [],
    recommendations = [],
    limitations = [],
  } = response;

  const hasPoints = points.length > 0;
  const hasAnySummary = summary && summary.trim().length > 0;

  return (
    <div className="space-y-3 text-xs select-text" data-testid="copilot-bullet-response">
      {/* Optional heading */}
      {heading && (
        <h3 className="text-sm font-bold text-primary leading-snug border-b border-border-subtle pb-1.5">
          {heading}
        </h3>
      )}

      {/* Summary line — only when no bullet points to show */}
      {hasAnySummary && !hasPoints && (
        <p className="text-sm text-secondary leading-relaxed">{summary}</p>
      )}

      {/* Bullet cards */}
      {hasPoints && (
        <div className="space-y-2">
          {points.map((p, idx) => (
            <BulletCard key={idx} point={p} index={idx} />
          ))}
        </div>
      )}

      {/* Confirmed */}
      <SubList items={confirmed} icon="✓" iconClass="text-green-500" label="Confirmed" />

      {/* Still Unconfirmed */}
      <SubList items={unconfirmed} icon="⚠" iconClass="text-yellow-500" label="Still Unconfirmed" />

      {/* Recommended Next Steps */}
      {recommendations.length > 0 && (
        <div className="space-y-1.5 pt-1 select-text">
          <h4 className="text-[10px] font-bold uppercase tracking-wider text-muted select-none">
            Recommended Next Steps
          </h4>
          <ol className="space-y-1.5 pl-0">
            {recommendations.map((r, idx) => (
              <li key={idx} className="flex gap-2 items-start text-xs text-secondary">
                <span className="text-accent font-bold select-none flex-shrink-0">→</span>
                <span className="flex-1 leading-relaxed">{renderInline(r)}</span>
              </li>
            ))}
          </ol>
        </div>
      )}

      {/* Limitations */}
      <SubList items={limitations} icon="⚡" iconClass="text-orange-400" label="Limitations" />
    </div>
  );
}
