/**
 * CopilotPanel.tsx
 *
 * Single-pipeline Copilot renderer.
 *
 * Flow:
 *   API response
 *   → extractRawText()        pick the right field from any API shape
 *   → unwrapAnswer()          recursively strip JSON envelopes, remove "question"
 *   → parseToPoints()         deterministic markdown/prose → CopilotResponseShape
 *   → <CopilotBulletResponse> pure bullet-card renderer (no JSON, no paragraphs)
 *
 * NEVER renders: raw JSON, "question", "answer" keys, numbered fragments 01/02.
 */

import {
  Bot, Info, Send, Loader2, ShieldCheck, AlertTriangle,
  Sparkles, HelpCircle, FileSearch, ShieldAlert, Cpu,
} from 'lucide-react';
import React, { useState, useRef, useEffect } from 'react';
import { useMutation } from '@tanstack/react-query';
import {
  generateQA,
  generateSummary,
  generateFindingExplanation,
  generateMitreExplanation,
  generateHypothesisExplanation,
  generateRootCauseExplanation,
  generateImpactExplanation,
} from '../api';
import { Badge } from '../../../components/ui/Badge';
import { Button } from '../../../components/ui/Button';
import {
  CopilotBulletResponse,
  type CopilotResponseShape,
  type CopilotPoint,
} from './CopilotBulletResponse';

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const SYSTEM_QUERIES = [
  'What does M1 do?',
  'What does M2 do?',
  'What does M3 do?',
  'What does M4 do?',
  'Where is evidence stored in PostgreSQL vs MinIO?',
  'What is the difference between a Finding and a Hypothesis?',
  'What is a Root Cause and Impact Assessment?',
  'How do I export the investigation PDF report?',
];

const PRESET_INVESTIGATION_PROMPTS = [
  'Why is this case suspicious?',
  'What are the highest-risk findings?',
  'What evidence supports suspected C2 activity?',
  'Which hosts are most important in this timeline?',
  'What evidence supports possible data exfiltration?',
  'What should I investigate next?',
  'How can I contain or remediate this activity?',
  'What evidence is missing or unproven?',
];

// ─────────────────────────────────────────────────────────────────────────────
// Message type
// ─────────────────────────────────────────────────────────────────────────────

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  status?: string;
  copilotResponse?: CopilotResponseShape;
  isError?: boolean;
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 1 — extractRawText
// Pull the answer string from any API response shape.
// ─────────────────────────────────────────────────────────────────────────────

function extractRawText(data: any, defaultText: string): string {
  if (!data || typeof data !== 'object') return defaultText;

  // Fully structured backend response — handled in buildCopilotResponse separately
  if (data.copilot_response && typeof data.copilot_response === 'object') {
    return '__STRUCTURED__';
  }

  // { investigator_answers: { "question": "answer text" } }
  if (data.investigator_answers && typeof data.investigator_answers === 'object') {
    const values = Object.values(data.investigator_answers);
    if (values.length > 0 && values[0]) return String(values[0]);
  }

  if (data.explanation) return String(data.explanation);
  if (data.summary && !data.points) return String(data.summary);
  if (data.answer) return String(data.answer);
  if (data.response) return String(data.response);

  return defaultText;
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 2 — unwrapAnswer
// Recursively unwrap nested JSON envelopes. Output: clean plain-text string.
// ─────────────────────────────────────────────────────────────────────────────

export function unwrapAnswer(value: unknown, depth = 0): string {
  if (depth > 10) return String(value ?? '');

  if (Array.isArray(value)) return unwrapAnswer(value[0], depth + 1);

  if (value !== null && typeof value === 'object') {
    const obj = value as Record<string, unknown>;
    if (obj.answer !== undefined) return unwrapAnswer(obj.answer, depth + 1);
    if (obj.explanation !== undefined) return unwrapAnswer(obj.explanation, depth + 1);
    if (obj.summary !== undefined && !obj.points) return unwrapAnswer(obj.summary, depth + 1);
    if (obj.response !== undefined) return unwrapAnswer(obj.response, depth + 1);
    return sanitizeJsonArtifacts(JSON.stringify(value));
  }

  if (typeof value !== 'string') return String(value ?? '');

  let text = value.trim();

  // Strip markdown code fences
  if (text.startsWith('```json')) text = text.slice(7).trim();
  else if (text.startsWith('```')) text = text.slice(3).trim();
  if (text.endsWith('```')) text = text.slice(0, -3).trim();

  // Try JSON parse and recurse
  if ((text.startsWith('{') && text.endsWith('}')) ||
      (text.startsWith('[') && text.endsWith(']'))) {
    try {
      const parsed = JSON.parse(text);
      return unwrapAnswer(parsed, depth + 1);
    } catch (_) { /* not JSON */ }
  }

  // Strip leading label prefixes
  text = text.replace(/^(question|your question was|asked|user asked)\s*[:\-]\s*/i, '');
  text = text.replace(/^(answer|response)\s*[:\-]\s*/i, '');

  return text.trim();
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 2b — sanitizeJsonArtifacts
// Remove residual JSON structural characters after unwrapping.
// ─────────────────────────────────────────────────────────────────────────────

function sanitizeJsonArtifacts(text: string): string {
  return text
    .replace(/^\s*[{}\[\]]\s*$/gm, '')
    .replace(/"(question|answer|summary|points|status|response|explanation)"\s*:\s*/gi, '')
    .replace(/\\"/g, '"')
    .replace(/,\s*\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 3 — parseToPoints
// Deterministic markdown/prose → CopilotResponseShape
// ─────────────────────────────────────────────────────────────────────────────

const SECTION_CONFIRMED = ['confirmed', 'supported finding'];
const SECTION_UNCONFIRMED = ['unconfirmed', 'not confirmed', 'unclear', 'missing evidence'];
const SECTION_RECOMMEND = ['recommend', 'next step', 'action', 'remediat', 'contain'];
const SECTION_LIMIT = ['limitation', 'gap', 'missing telemetry', 'unavailable'];

function sectionType(sec: string): 'confirmed' | 'unconfirmed' | 'recommend' | 'limit' | 'points' {
  const s = sec.toLowerCase();
  if (SECTION_CONFIRMED.some(k => s.includes(k))) return 'confirmed';
  if (SECTION_UNCONFIRMED.some(k => s.includes(k))) return 'unconfirmed';
  if (SECTION_RECOMMEND.some(k => s.includes(k))) return 'recommend';
  if (SECTION_LIMIT.some(k => s.includes(k))) return 'limit';
  return 'points';
}

function extractTitleExplanation(text: string): { title: string; explanation: string } {
  // Strip list marker prefix (numbered or single-char bullet) but NOT ** which is bold syntax
  // Only strip: "1. ", "- ", "* ", "+ ", "• " — single char bullets, not "**"
  const clean = text.replace(/^(\d+\.\s+|[-+•]\s+|\*(?!\*)\s+)/, '').trim();

  // **Bold** — rest
  const boldM = clean.match(/^\*\*(.*?)\*\*\s*(?:[:\-\u2014]\s*(.*))?$/);
  if (boldM) {
    return { title: boldM[1].trim(), explanation: (boldM[2] ?? '').trim() };
  }

  // Title: explanation (colon-separated)
  const colonM = clean.match(/^([A-Za-z0-9][A-Za-z0-9 \-./T()]+?)\s*:\s+(.+)$/);
  if (colonM && colonM[1].trim().length <= 50 && colonM[2].trim().length > 0) {
    return { title: colonM[1].trim(), explanation: colonM[2].trim() };
  }

  // Title — explanation (dash-separated)
  const dashM = clean.match(/^(.+?)\s+[\-\u2014]{1,2}\s+(.+)$/);
  if (dashM && dashM[1].trim().length <= 60) {
    return { title: dashM[1].trim(), explanation: dashM[2].trim() };
  }

  // Long sentence (> 6 words) → first 4 words = title
  const words = clean.split(/\s+/);
  if (words.length > 6) {
    const titleWords = words.slice(0, 4).join(' ').replace(/[.,;:-]+$/, '');
    return { title: titleWords, explanation: clean };
  }

  // Short phrase (≤ 6 words) — use full text as title (it IS the meaningful label)
  return { title: clean, explanation: '' };
}

function paragraphToPoints(para: string): CopilotPoint[] {
  const sentences = para
    .split(/(?<=[.!?])\s+(?=[A-Z"'])/)
    .map(s => s.trim())
    .filter(s => s.length > 0);
  return sentences.map(s => extractTitleExplanation(s));
}

export function parseToPoints(text: string): CopilotResponseShape {
  if (!text || !text.trim()) {
    return { summary: 'No response provided.', points: [] };
  }

  const lines = text.split('\n').map(l => l.trim()).filter(Boolean);
  let heading = '';
  let currentSection = 'points';
  const points: CopilotPoint[] = [];
  const confirmed: string[] = [];
  const unconfirmed: string[] = [];
  const recommendations: string[] = [];
  const limitations: string[] = [];

  for (const line of lines) {
    // Section heading (## or ###)
    if (line.startsWith('#')) {
      const rawHeading = line.replace(/^#+\s*/, '').trim();
      const secType = sectionType(rawHeading);
      currentSection = secType;
      if (secType === 'points' && !heading) heading = rawHeading;
      continue;
    }

    const listM = line.match(/^(\d+\.|[-*+•])\s*(.*)/);
    const content = listM ? listM[2].trim() : line;

    // Sub-item (indented) — append to last point's explanation
    const isSubItem = /^(\s{2,}|\t)[-*+•]\s/.test(' ' + line);
    if (isSubItem && points.length > 0 && currentSection === 'points') {
      const cleaned = content.replace(/`([^`]+)`/g, '$1').trim();
      const last = points[points.length - 1];
      last.explanation = last.explanation
        ? last.explanation + ' · ' + cleaned
        : cleaned;
      continue;
    }

    switch (currentSection) {
      case 'confirmed': confirmed.push(content); break;
      case 'unconfirmed': unconfirmed.push(content); break;
      case 'recommend': recommendations.push(content); break;
      case 'limit': limitations.push(content); break;
      default: {
        if (listM) {
          const { title, explanation } = extractTitleExplanation(content);
          points.push({ title, explanation });
        } else if (line.length < 80 && !/\.\s/.test(line)) {
          const { title, explanation } = extractTitleExplanation(line);
          points.push({ title, explanation });
        } else {
          points.push(...paragraphToPoints(line));
        }
      }
    }
  }

  if (
    points.length === 0 &&
    confirmed.length === 0 &&
    recommendations.length === 0 &&
    limitations.length === 0
  ) {
    return { heading: heading || undefined, summary: text.substring(0, 400).trim(), points: [] };
  }

  return {
    heading: heading || undefined,
    summary: '',
    points,
    confirmed,
    unconfirmed,
    recommendations,
    limitations,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// STEP 4 — buildCopilotResponse
// Single entry point: API data → CopilotResponseShape
// ─────────────────────────────────────────────────────────────────────────────

export function buildCopilotResponse(
  data: any,
  defaultText = 'No response provided.'
): CopilotResponseShape {
  // A. Backend returned fully structured copilot_response with explicit points
  if (data?.copilot_response && typeof data.copilot_response === 'object') {
    const res = data.copilot_response;
    if (Array.isArray(res.points) && res.points.length > 0) {
      return {
        heading: res.heading ?? undefined,
        summary: res.summary ?? '',
        points: res.points.map((p: any) => ({
          title: p.title || 'Observation',
          explanation: p.explanation || '',
          evidence_ids: Array.isArray(p.evidence_ids) ? p.evidence_ids : [],
          finding_ids: Array.isArray(p.finding_ids) ? p.finding_ids : [],
          technique_ids: Array.isArray(p.technique_ids) ? p.technique_ids : [],
          status: p.status ?? undefined,
          confidence: typeof p.confidence === 'number' ? p.confidence : undefined,
        })),
        confirmed: Array.isArray(res.confirmed) ? res.confirmed : [],
        unconfirmed: Array.isArray(res.unconfirmed) ? res.unconfirmed : [],
        recommendations: Array.isArray(res.recommendations) ? res.recommendations : [],
        limitations: Array.isArray(res.limitations) ? res.limitations : [],
      };
    }
    // Has raw_unstructured or summary but no points → parse it
    const fallback = res.raw_unstructured || res.summary || defaultText;
    return parseToPoints(unwrapAnswer(fallback));
  }

  // B. Extract raw text field, then unwrap + parse
  const rawField = extractRawText(data, defaultText);
  const cleanText = unwrapAnswer(rawField);
  return parseToPoints(cleanText);
}

// ─────────────────────────────────────────────────────────────────────────────
// renderMarkdown — kept only for the System Architecture tab
// ─────────────────────────────────────────────────────────────────────────────

function renderMarkdown(content: string) {
  const lines = content.split('\n');
  const elements: React.ReactNode[] = [];
  let listItems: React.ReactNode[] = [];

  const parseInline = (text: string): React.ReactNode[] =>
    text.split(/(\*\*.*?\*\*|`.*?`)/).map((tok, i) => {
      if (tok.startsWith('**') && tok.endsWith('**'))
        return <strong key={i} className="font-semibold text-primary">{tok.slice(2, -2)}</strong>;
      if (tok.startsWith('`') && tok.endsWith('`'))
        return <code key={i} className="px-1 py-0.5 rounded bg-surface-elevated border border-border-subtle text-secondary font-mono text-[11px]">{tok.slice(1, -1)}</code>;
      return tok;
    });

  const flush = (k: number) => {
    if (listItems.length > 0) {
      elements.push(<ul key={`ul-${k}`} className="list-disc pl-5 my-2 space-y-1 text-secondary">{listItems}</ul>);
      listItems = [];
    }
  };

  for (let i = 0; i < lines.length; i++) {
    const t = lines[i].trim();
    if (!t) { flush(i); elements.push(<div key={`sp-${i}`} className="h-2" />); continue; }
    if (t.startsWith('###')) { flush(i); elements.push(<h3 key={i} className="text-sm font-bold mt-4 mb-2 text-primary border-b border-border-subtle pb-1">{t.slice(3).trim()}</h3>); continue; }
    if (t.startsWith('##')) { flush(i); elements.push(<h2 key={i} className="text-base font-bold mt-4 mb-2 text-primary">{t.slice(2).trim()}</h2>); continue; }
    const bm = lines[i].match(/^(\s*)[-*+]\s(.*)/);
    if (bm) {
      if (bm[1].length > 0) { flush(i); elements.push(<div key={i} className="pl-6 flex gap-1.5 my-1 text-xs text-secondary"><span>•</span><span>{parseInline(bm[2])}</span></div>); }
      else listItems.push(<li key={i} className="text-xs">{parseInline(bm[2])}</li>);
      continue;
    }
    const nm = lines[i].match(/^(\s*)(\d+)\.\s(.*)/);
    if (nm) { flush(i); elements.push(<div key={i} className={`flex gap-1.5 my-1 ${nm[1].length > 0 ? 'pl-6 text-xs' : 'text-sm font-medium text-primary'}`}><span className="text-accent font-semibold">{nm[2]}.</span><span>{parseInline(nm[3])}</span></div>); continue; }
    flush(i);
    elements.push(<p key={i} className="text-sm my-1 text-secondary leading-relaxed">{parseInline(lines[i])}</p>);
  }
  flush(lines.length);
  return <div className="space-y-1 select-text">{elements}</div>;
}

// ─────────────────────────────────────────────────────────────────────────────
// CopilotPanel — main component
// ─────────────────────────────────────────────────────────────────────────────

interface CopilotPanelProps { caseId: string; }

export function CopilotPanel({ caseId }: CopilotPanelProps) {
  const [selectedPrompt, setSelectedPrompt] = useState<string>('');
  const [targetId, setTargetId] = useState<string>('');
  const [activeTab, setActiveTab] = useState<
    'ask' | 'summary' | 'finding' | 'mitre' | 'hypothesis' | 'root_cause' | 'impact' | 'system'
  >('ask');
  const [messages, setMessages] = useState<Message[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  const addAssistantMessage = (data: any, defaultText = 'No response provided.') => {
    const errorMessages: Record<string, string> = {
      LLM_UNAVAILABLE: '⚠️ AI Copilot is offline or the local Ollama service is unreachable on localhost:11434.',
      LLM_MODEL_UNAVAILABLE: '⚠️ The configured Qwen model is unavailable in your local Ollama instance.',
      LLM_UNGROUNDED: '⚠️ Insufficient forensic evidence in this case context to generate a grounded response.',
      LLM_INVALID_RESPONSE: '⚠️ AI Copilot received an invalid response format or unparseable target ID.',
    };

    if (data?.status && errorMessages[data.status]) {
      setMessages(prev => [...prev, {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: errorMessages[data.status],
        status: data.status,
        isError: true,
      }]);
      return;
    }

    const copilotResponse = buildCopilotResponse(data, defaultText);
    setMessages(prev => [...prev, {
      id: crypto.randomUUID(),
      role: 'assistant',
      content: copilotResponse.summary || defaultText,
      status: data?.status,
      copilotResponse,
    }]);
  };

  const askMutation = useMutation({
    mutationFn: (q: string) => generateQA(caseId, q),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`),
  });
  const summaryMutation = useMutation({
    mutationFn: () => generateSummary(caseId),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`),
  });
  const findingMutation = useMutation({
    mutationFn: (id: string) => generateFindingExplanation(caseId, id),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`),
  });
  const mitreMutation = useMutation({
    mutationFn: (id: string) => generateMitreExplanation(caseId, id),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`),
  });
  const hypothesisMutation = useMutation({
    mutationFn: (id: string) => generateHypothesisExplanation(caseId, id),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`),
  });
  const rootCauseMutation = useMutation({
    mutationFn: (id: string) => generateRootCauseExplanation(caseId, id),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`),
  });
  const impactMutation = useMutation({
    mutationFn: (id: string) => generateImpactExplanation(caseId, id),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`),
  });

  const isPending =
    askMutation.isPending || summaryMutation.isPending || findingMutation.isPending ||
    mitreMutation.isPending || hypothesisMutation.isPending || rootCauseMutation.isPending ||
    impactMutation.isPending;

  const handleSendPrompt = (text: string) => {
    if (!text.trim() || isPending) return;
    setMessages(prev => [...prev, { id: crypto.randomUUID(), role: 'user', content: text }]);
    setSelectedPrompt('');
    askMutation.mutate(text);
  };

  const handleExecuteTargetExplanation = (type: 'finding' | 'mitre' | 'hypothesis' | 'root_cause' | 'impact') => {
    if (!targetId.trim() || isPending) return;
    setMessages(prev => [...prev, { id: crypto.randomUUID(), role: 'user', content: `Explain ${type.replace('_', ' ')}: ${targetId}` }]);
    if (type === 'finding') findingMutation.mutate(targetId);
    else if (type === 'mitre') mitreMutation.mutate(targetId);
    else if (type === 'hypothesis') hypothesisMutation.mutate(targetId);
    else if (type === 'root_cause') rootCauseMutation.mutate(targetId);
    else if (type === 'impact') impactMutation.mutate(targetId);
  };

  const handleSummaryAction = () => {
    if (isPending) return;
    setMessages(prev => [...prev, { id: crypto.randomUUID(), role: 'user', content: 'Generate Investigation Summary' }]);
    summaryMutation.mutate();
  };

  const NAV_ITEMS = [
    { id: 'ask' as const, icon: <HelpCircle className="h-3.5 w-3.5" />, label: 'Ask Copilot', action: () => setActiveTab('ask') },
    { id: 'summary' as const, icon: <Sparkles className="h-3.5 w-3.5" />, label: 'Case Summary', action: handleSummaryAction },
    { id: 'finding' as const, icon: <FileSearch className="h-3.5 w-3.5" />, label: 'Explain Finding', action: () => setActiveTab('finding') },
    { id: 'mitre' as const, icon: <ShieldAlert className="h-3.5 w-3.5" />, label: 'MITRE ATT&CK', action: () => setActiveTab('mitre') },
    { id: 'hypothesis' as const, icon: <AlertTriangle className="h-3.5 w-3.5" />, label: 'Hypothesis', action: () => setActiveTab('hypothesis') },
    { id: 'root_cause' as const, icon: <ShieldCheck className="h-3.5 w-3.5" />, label: 'Root Cause', action: () => setActiveTab('root_cause') },
    { id: 'system' as const, icon: <Cpu className="h-3.5 w-3.5" />, label: 'System Architecture', action: () => setActiveTab('system') },
  ];

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Header */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between pb-3 border-b border-border-subtle gap-2">
        <div className="flex items-center gap-2">
          <Bot className="h-5 w-5 text-accent" />
          <div>
            <h3 className="text-sm font-semibold text-primary flex items-center gap-2">
              NetSleuth AI Forensic Copilot
              <Badge variant="info" className="text-[10px]">AI-ASSISTED</Badge>
            </h3>
            <p className="text-xs text-muted">Grounded in M3 correlation data • Read-Only Advisory Assistant</p>
          </div>
        </div>
        <Badge variant="info" className="text-[10px] font-mono border border-border-subtle bg-surface-elevated text-secondary">
          AUTHORITATIVE DATA COMES FROM M3
        </Badge>
      </div>

      {/* Navigation */}
      <div className="flex items-center gap-1 overflow-x-auto pb-1 text-xs border-b border-border-subtle">
        {NAV_ITEMS.map(({ id, icon, label, action }) => (
          <button
            key={id}
            onClick={() => { if (!isPending) { action(); if (id !== 'summary') setActiveTab(id); } }}
            disabled={isPending}
            className={`px-2.5 py-1.5 rounded font-medium transition-colors flex items-center gap-1 whitespace-nowrap disabled:opacity-50 disabled:cursor-not-allowed ${
              activeTab === id ? 'bg-accent text-white' : 'text-secondary hover:text-primary hover:bg-surface-elevated'
            }`}
          >
            {icon} {label}
          </button>
        ))}
      </div>

      {/* Target ID Input */}
      {(['finding', 'mitre', 'hypothesis', 'root_cause', 'impact'] as const).some(t => t === activeTab) && (
        <div className="flex items-center gap-2 p-2 bg-surface-elevated rounded border border-border-subtle">
          <input
            type="text"
            value={targetId}
            onChange={(e) => setTargetId(e.target.value)}
            placeholder={`Enter ${activeTab.replace('_', ' ')} ID (e.g. ${activeTab === 'mitre' ? 'T1071.001' : 'f1'})…`}
            className="flex-1 px-3 py-1.5 text-xs bg-background border border-border-subtle rounded text-primary focus:outline-none focus:border-accent font-mono"
          />
          <Button
            size="sm"
            variant="secondary"
            onClick={() => handleExecuteTargetExplanation(activeTab as any)}
            disabled={!targetId.trim() || isPending}
          >
            Explain {activeTab.replace('_', ' ')}
          </Button>
        </div>
      )}

      {/* Messages */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-2 min-h-[300px]">
        {messages.length === 0 ? (
          <div className="space-y-6">
            {activeTab === 'system' && (
              <div className="space-y-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <Cpu className="h-3.5 w-3.5 text-accent" /> NetSleuth Architecture Guide
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {SYSTEM_QUERIES.map(q => (
                    <button key={q} onClick={() => handleSendPrompt(q)} disabled={isPending}
                      className="text-left p-2.5 rounded border text-xs transition-colors border-border-subtle bg-surface-elevated/40 text-secondary hover:text-primary hover:border-accent hover:bg-accent/10 disabled:opacity-50 disabled:cursor-not-allowed">
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            )}
            {activeTab !== 'system' && (
              <div className="space-y-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <Info className="h-3.5 w-3.5 text-accent" /> Preset Forensic Investigator Queries
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {PRESET_INVESTIGATION_PROMPTS.map(prompt => (
                    <button key={prompt} onClick={() => handleSendPrompt(prompt)} disabled={isPending}
                      className="text-left p-2.5 rounded border text-xs transition-colors border-border-subtle bg-surface-elevated/40 text-secondary hover:text-primary hover:border-accent hover:bg-accent/10 disabled:opacity-50 disabled:cursor-not-allowed">
                      {prompt}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          messages.map(msg => (
            <div key={msg.id} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}>
              {msg.role === 'assistant' && (
                <div className="flex-shrink-0 h-7 w-7 rounded-full bg-accent/20 flex items-center justify-center border border-accent/40">
                  <Bot className="h-4 w-4 text-accent" />
                </div>
              )}
              <div className={`text-sm p-4 rounded-lg max-w-[90%] ${
                msg.role === 'user'
                  ? 'bg-accent text-white rounded-tr-none'
                  : 'bg-surface-elevated border border-border-subtle text-primary rounded-tl-none'
              }`}>
                {msg.role === 'assistant' && (
                  <div className="flex items-center justify-between pb-2 mb-3 border-b border-border-subtle text-[11px] font-mono text-muted select-none">
                    <span>AI-ASSISTED ANALYSIS</span>
                    <span>GROUNDED · M3</span>
                  </div>
                )}
                {msg.role === 'assistant' ? (
                  msg.isError ? (
                    <p className="text-xs text-yellow-500 leading-relaxed">{msg.content}</p>
                  ) : msg.copilotResponse ? (
                    <CopilotBulletResponse response={msg.copilotResponse} />
                  ) : (
                    <p className="text-xs text-secondary">{msg.content}</p>
                  )
                ) : (
                  <span>{msg.content}</span>
                )}
              </div>
            </div>
          ))
        )}

        {isPending && (
          <div className="flex gap-3 justify-start">
            <div className="flex-shrink-0 h-7 w-7 rounded-full bg-accent/20 flex items-center justify-center border border-accent/40">
              <Bot className="h-4 w-4 text-accent" />
            </div>
            <div className="text-sm p-4 rounded-lg max-w-[85%] bg-surface-elevated border border-border-subtle text-primary rounded-tl-none flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin text-accent" />
              Assembling evidence context & querying local Qwen LLM…
            </div>
          </div>
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Query Input */}
      <div className="space-y-2 pt-3 border-t border-border-subtle flex-shrink-0">
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={selectedPrompt}
            onChange={(e) => setSelectedPrompt(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSendPrompt(selectedPrompt)}
            placeholder="Ask Copilot about findings, C2, DNS, exfiltration, or system architecture…"
            disabled={isPending}
            className="flex-1 px-3 py-2 text-xs bg-surface-elevated border border-border-subtle rounded text-primary focus:outline-none focus:border-accent disabled:opacity-50"
          />
          <button
            onClick={() => handleSendPrompt(selectedPrompt)}
            disabled={isPending || !selectedPrompt.trim()}
            className="flex items-center gap-1 px-4 py-2 text-xs bg-accent text-white rounded font-medium hover:bg-accent/90 disabled:opacity-50 transition-colors"
          >
            {isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
            Send
          </button>
        </div>
      </div>
    </div>
  );
}

