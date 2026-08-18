import { Bot, AlertCircle, Info, Send } from 'lucide-react';
import { useState } from 'react';

const PRESET_PROMPTS = [
  'Why is this case suspicious?',
  'What are the highest-risk findings?',
  'What evidence supports suspected C2 activity?',
  'Which hosts are most important in this timeline?',
  'What evidence supports possible data exfiltration?',
  'What should I investigate next?',
];

interface CopilotPanelProps {
  caseId: string;
}

export function CopilotPanel({ caseId }: CopilotPanelProps) {
  const [selectedPrompt, setSelectedPrompt] = useState<string>('');

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center gap-2 pb-3 border-b border-border-subtle">
        <Bot className="h-5 w-5 text-accent" />
        <div>
          <h3 className="text-sm font-semibold text-primary">NetSleuth AI Copilot</h3>
          <p className="text-xs text-muted">Evidence-grounded forensic assistant for case {caseId.slice(0, 8)}…</p>
        </div>
      </div>

      {/* Official Status Panel per FE-7 directive */}
      <div className="p-4 rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-200 space-y-2">
        <div className="flex items-center gap-2 font-semibold text-xs text-amber-300">
          <AlertCircle className="h-4 w-4 text-amber-400 flex-shrink-0" />
          Copilot API Unavailable / Contract Not Configured
        </div>
        <p className="text-xs text-amber-200/90 leading-relaxed">
          The backend Copilot API endpoint (e.g., <code className="font-mono text-[11px] bg-black/20 px-1 py-0.5 rounded">/api/v1/cases/{'{case_id}'}/copilot</code>) is currently absent from the frozen OpenAPI contract (<code className="font-mono text-[11px] bg-black/20 px-1 py-0.5 rounded">docs/api/openapi-v1.json</code>).
        </p>
        <p className="text-[11px] text-amber-300/80 pt-1">
          Per platform integrity directives, client-side fake LLM inference is strictly prohibited. The Copilot UI abstraction is ready for immediate backend binding once the API is deployed.
        </p>
      </div>

      {/* Preset Investigator Prompts */}
      <div className="space-y-2">
        <label className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
          <Info className="h-3.5 w-3.5" /> Preset Investigator Queries (Ready for API)
        </label>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {PRESET_PROMPTS.map((prompt) => (
            <button
              key={prompt}
              onClick={() => setSelectedPrompt(prompt)}
              className={`text-left p-2.5 rounded border text-xs transition-colors ${
                selectedPrompt === prompt
                  ? 'border-accent bg-accent/10 text-primary font-medium'
                  : 'border-border-subtle bg-surface-elevated/40 text-secondary hover:text-primary hover:border-border-subtle'
              }`}
            >
              {prompt}
            </button>
          ))}
        </div>
      </div>

      {/* Query Input Abstraction */}
      <div className="space-y-2 pt-2 border-t border-border-subtle">
        <div className="flex items-center gap-2">
          <input
            type="text"
            value={selectedPrompt}
            onChange={(e) => setSelectedPrompt(e.target.value)}
            placeholder="Ask AI Copilot about this case…"
            disabled
            className="flex-1 px-3 py-2 text-xs bg-surface-elevated border border-border-subtle rounded text-muted cursor-not-allowed"
          />
          <button
            disabled
            className="flex items-center gap-1 px-3.5 py-2 text-xs bg-accent/40 text-white/50 rounded font-medium cursor-not-allowed"
          >
            <Send className="h-3.5 w-3.5" />
            Send
          </button>
        </div>
        <p className="text-[10px] text-muted">
          Input disabled until backend Copilot API endpoint is connected.
        </p>
      </div>
    </div>
  );
}
