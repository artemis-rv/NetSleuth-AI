import { Bot, Info, Send, Loader2, ShieldCheck, AlertTriangle, Sparkles, HelpCircle, FileSearch, ShieldAlert, Cpu } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';
import { useMutation } from '@tanstack/react-query';
import { 
  generateQA, 
  generateSummary, 
  generateFindingExplanation, 
  generateMitreExplanation,
  generateHypothesisExplanation,
  generateRootCauseExplanation,
  generateImpactExplanation
} from '../api';
import { Badge } from '../../../components/ui/Badge';
import { Button } from '../../../components/ui/Button';

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

interface CopilotPanelProps {
  caseId: string;
}

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  status?: string;
}

export function CopilotPanel({ caseId }: CopilotPanelProps) {
  const [selectedPrompt, setSelectedPrompt] = useState<string>('');
  const [targetId, setTargetId] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'ask' | 'summary' | 'finding' | 'mitre' | 'hypothesis' | 'root_cause' | 'impact' | 'system'>('ask');
  const [messages, setMessages] = useState<Message[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const addAssistantMessage = (data: any, defaultText: string = 'No response provided.') => {
    let content = defaultText;
    if (data.status === 'SUCCESS') {
      content =
        data.explanation ||
        data.summary ||
        (data.investigator_answers && Object.values(data.investigator_answers)[0]) ||
        data.response ||
        defaultText;
    } else if (data.status === 'LLM_UNAVAILABLE') {
      content = '⚠️ AI Copilot is offline or the local Ollama service is unreachable on localhost:11434.';
    } else if (data.status === 'LLM_MODEL_UNAVAILABLE') {
      content = '⚠️ The configured Qwen model is unavailable in your local Ollama instance.';
    } else if (data.status === 'LLM_UNGROUNDED') {
      content = '⚠️ Insufficient forensic evidence in this case context to generate an ungrounded claim.';
    } else if (data.status === 'LLM_INVALID_RESPONSE') {
      content = '⚠️ AI Copilot received an invalid response format or unparseable target ID.';
    }

    setMessages(prev => [...prev, {
      id: crypto.randomUUID(),
      role: 'assistant',
      content,
      status: data.status
    }]);
  };

  const askMutation = useMutation({
    mutationFn: (q: string) => generateQA(caseId, q),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`)
  });

  const summaryMutation = useMutation({
    mutationFn: () => generateSummary(caseId),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`)
  });

  const findingMutation = useMutation({
    mutationFn: (id: string) => generateFindingExplanation(caseId, id),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`)
  });

  const mitreMutation = useMutation({
    mutationFn: (id: string) => generateMitreExplanation(caseId, id),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`)
  });

  const hypothesisMutation = useMutation({
    mutationFn: (id: string) => generateHypothesisExplanation(caseId, id),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`)
  });

  const rootCauseMutation = useMutation({
    mutationFn: (id: string) => generateRootCauseExplanation(caseId, id),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`)
  });

  const impactMutation = useMutation({
    mutationFn: (id: string) => generateImpactExplanation(caseId, id),
    onSuccess: (data) => addAssistantMessage(data),
    onError: (err: any) => addAssistantMessage({ status: 'LLM_UNAVAILABLE' }, `Error: ${err.message}`)
  });

  const isPending = 
    askMutation.isPending || 
    summaryMutation.isPending || 
    findingMutation.isPending || 
    mitreMutation.isPending || 
    hypothesisMutation.isPending || 
    rootCauseMutation.isPending || 
    impactMutation.isPending;

  const handleSendPrompt = (text: string) => {
    if (!text.trim() || isPending) return;
    setMessages(prev => [...prev, { id: crypto.randomUUID(), role: 'user', content: text }]);
    setSelectedPrompt('');
    askMutation.mutate(text);
  };

  const handleExecuteTargetExplanation = (type: 'finding' | 'mitre' | 'hypothesis' | 'root_cause' | 'impact') => {
    if (!targetId.trim() || isPending) return;
    const promptText = `Explain ${type.replace('_', ' ')}: ${targetId}`;
    setMessages(prev => [...prev, { id: crypto.randomUUID(), role: 'user', content: promptText }]);
    
    if (type === 'finding') findingMutation.mutate(targetId);
    else if (type === 'mitre') mitreMutation.mutate(targetId);
    else if (type === 'hypothesis') hypothesisMutation.mutate(targetId);
    else if (type === 'root_cause') rootCauseMutation.mutate(targetId);
    else if (type === 'impact') impactMutation.mutate(targetId);
  };

  const handleSummaryAction = () => {
    setMessages(prev => [...prev, { id: crypto.randomUUID(), role: 'user', content: 'Generate Investigation Summary' }]);
    summaryMutation.mutate();
  };

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Header Badges */}
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

      {/* Quick Action Navigation Bar */}
      <div className="flex items-center gap-1 overflow-x-auto pb-1 text-xs border-b border-border-subtle">
        <button
          onClick={() => setActiveTab('ask')}
          className={`px-2.5 py-1.5 rounded font-medium transition-colors flex items-center gap-1 whitespace-nowrap ${
            activeTab === 'ask' ? 'bg-accent text-white' : 'text-secondary hover:text-primary hover:bg-surface-elevated'
          }`}
        >
          <HelpCircle className="h-3.5 w-3.5" /> Ask Copilot
        </button>
        <button
          onClick={() => { setActiveTab('summary'); handleSummaryAction(); }}
          className={`px-2.5 py-1.5 rounded font-medium transition-colors flex items-center gap-1 whitespace-nowrap ${
            activeTab === 'summary' ? 'bg-accent text-white' : 'text-secondary hover:text-primary hover:bg-surface-elevated'
          }`}
        >
          <Sparkles className="h-3.5 w-3.5" /> Case Summary
        </button>
        <button
          onClick={() => setActiveTab('finding')}
          className={`px-2.5 py-1.5 rounded font-medium transition-colors flex items-center gap-1 whitespace-nowrap ${
            activeTab === 'finding' ? 'bg-accent text-white' : 'text-secondary hover:text-primary hover:bg-surface-elevated'
          }`}
        >
          <FileSearch className="h-3.5 w-3.5" /> Explain Finding
        </button>
        <button
          onClick={() => setActiveTab('mitre')}
          className={`px-2.5 py-1.5 rounded font-medium transition-colors flex items-center gap-1 whitespace-nowrap ${
            activeTab === 'mitre' ? 'bg-accent text-white' : 'text-secondary hover:text-primary hover:bg-surface-elevated'
          }`}
        >
          <ShieldAlert className="h-3.5 w-3.5" /> MITRE ATT&CK
        </button>
        <button
          onClick={() => setActiveTab('hypothesis')}
          className={`px-2.5 py-1.5 rounded font-medium transition-colors flex items-center gap-1 whitespace-nowrap ${
            activeTab === 'hypothesis' ? 'bg-accent text-white' : 'text-secondary hover:text-primary hover:bg-surface-elevated'
          }`}
        >
          <AlertTriangle className="h-3.5 w-3.5" /> Hypothesis
        </button>
        <button
          onClick={() => setActiveTab('root_cause')}
          className={`px-2.5 py-1.5 rounded font-medium transition-colors flex items-center gap-1 whitespace-nowrap ${
            activeTab === 'root_cause' ? 'bg-accent text-white' : 'text-secondary hover:text-primary hover:bg-surface-elevated'
          }`}
        >
          <ShieldCheck className="h-3.5 w-3.5" /> Root Cause
        </button>
        <button
          onClick={() => setActiveTab('system')}
          className={`px-2.5 py-1.5 rounded font-medium transition-colors flex items-center gap-1 whitespace-nowrap ${
            activeTab === 'system' ? 'bg-accent text-white' : 'text-secondary hover:text-primary hover:bg-surface-elevated'
          }`}
        >
          <Cpu className="h-3.5 w-3.5" /> System Architecture
        </button>
      </div>

      {/* Action Specific Controls */}
      {['finding', 'mitre', 'hypothesis', 'root_cause', 'impact'].includes(activeTab) && (
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

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-2 min-h-[300px]">
        {messages.length === 0 ? (
          <div className="space-y-6">
            {/* System Architecture Prompts */}
            {activeTab === 'system' && (
              <div className="space-y-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <Cpu className="h-3.5 w-3.5 text-accent" /> NetSleuth Architecture Guide
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {SYSTEM_QUERIES.map((q) => (
                    <button
                      key={q}
                      onClick={() => handleSendPrompt(q)}
                      className="text-left p-2.5 rounded border text-xs transition-colors border-border-subtle bg-surface-elevated/40 text-secondary hover:text-primary hover:border-accent hover:bg-accent/10"
                    >
                      {q}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Presets */}
            {activeTab !== 'system' && (
              <div className="space-y-2">
                <label className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                  <Info className="h-3.5 w-3.5 text-accent" /> Preset Forensic Investigator Queries
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {PRESET_INVESTIGATION_PROMPTS.map((prompt) => (
                    <button
                      key={prompt}
                      onClick={() => handleSendPrompt(prompt)}
                      className="text-left p-2.5 rounded border text-xs transition-colors border-border-subtle bg-surface-elevated/40 text-secondary hover:text-primary hover:border-accent hover:bg-accent/10"
                    >
                      {prompt}
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.role === 'assistant' && (
                <div className="flex-shrink-0 h-7 w-7 rounded-full bg-accent/20 flex items-center justify-center border border-accent/40">
                  <Bot className="h-4 w-4 text-accent" />
                </div>
              )}
              <div
                className={`text-sm p-4 rounded-lg max-w-[90%] ${
                  msg.role === 'user'
                    ? 'bg-accent text-white rounded-tr-none'
                    : 'bg-surface-elevated border border-border-subtle text-primary rounded-tl-none whitespace-pre-wrap leading-relaxed'
                }`}
              >
                {msg.role === 'assistant' && (
                  <div className="flex items-center justify-between pb-2 mb-2 border-b border-border-subtle text-[11px] font-mono text-muted">
                    <span>AI-ASSISTED EXPLANATION</span>
                    <span>AUTHORITATIVE: M3</span>
                  </div>
                )}
                {msg.content}
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
