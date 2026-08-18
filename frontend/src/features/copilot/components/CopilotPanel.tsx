import { Bot, Info, Send, Loader2 } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';
import { useMutation } from '@tanstack/react-query';
import { generateQA } from '../api';

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

interface Message {
  id: string;
  role: 'user' | 'assistant';
  content: string;
}

export function CopilotPanel({ caseId }: CopilotPanelProps) {
  const [selectedPrompt, setSelectedPrompt] = useState<string>('');
  const [messages, setMessages] = useState<Message[]>([]);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  const { mutate: askQuestion, isPending } = useMutation({
    mutationFn: (q: string) => generateQA(caseId, q),
    onSuccess: (data) => {
      setMessages(prev => [...prev, {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: data.response || 'No response provided.'
      }]);
    },
    onError: (err: any) => {
      setMessages(prev => [...prev, {
        id: crypto.randomUUID(),
        role: 'assistant',
        content: `Error: ${err.message}`
      }]);
    }
  });

  const handleSend = () => {
    if (!selectedPrompt.trim() || isPending) return;
    const q = selectedPrompt;
    setMessages(prev => [...prev, {
      id: crypto.randomUUID(),
      role: 'user',
      content: q
    }]);
    setSelectedPrompt('');
    askQuestion(q);
  };

  return (
    <div className="flex flex-col h-full space-y-4">
      {/* Header */}
      <div className="flex flex-shrink-0 items-center gap-2 pb-3 border-b border-border-subtle">
        <Bot className="h-5 w-5 text-accent" />
        <div>
          <h3 className="text-sm font-semibold text-primary">NetSleuth AI Copilot</h3>
          <p className="text-xs text-muted">Evidence-grounded forensic assistant for case {caseId.slice(0, 8)}…</p>
        </div>
      </div>

      {/* Messages Area */}
      <div className="flex-1 overflow-y-auto space-y-4 pr-2 min-h-[300px]">
        {messages.length === 0 ? (
          <div className="space-y-4">
            {/* Preset Investigator Prompts */}
            <div className="space-y-2">
              <label className="text-xs font-semibold uppercase tracking-wider text-muted flex items-center gap-1.5">
                <Info className="h-3.5 w-3.5" /> Preset Investigator Queries
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {PRESET_PROMPTS.map((prompt) => (
                  <button
                    key={prompt}
                    onClick={() => setSelectedPrompt(prompt)}
                    className="text-left p-2.5 rounded border text-xs transition-colors border-border-subtle bg-surface-elevated/40 text-secondary hover:text-primary hover:border-accent hover:bg-accent/10"
                  >
                    {prompt}
                  </button>
                ))}
              </div>
            </div>
          </div>
        ) : (
          messages.map((msg) => (
            <div
              key={msg.id}
              className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : 'justify-start'}`}
            >
              {msg.role === 'assistant' && (
                <div className="flex-shrink-0 h-6 w-6 rounded-full bg-accent/20 flex items-center justify-center">
                  <Bot className="h-4 w-4 text-accent" />
                </div>
              )}
              <div
                className={`text-sm p-3 rounded-lg max-w-[85%] ${
                  msg.role === 'user'
                    ? 'bg-accent text-white rounded-tr-none'
                    : 'bg-surface-elevated border border-border-subtle text-primary rounded-tl-none whitespace-pre-wrap'
                }`}
              >
                {msg.content}
              </div>
            </div>
          ))
        )}
        {isPending && (
          <div className="flex gap-3 justify-start">
            <div className="flex-shrink-0 h-6 w-6 rounded-full bg-accent/20 flex items-center justify-center">
              <Bot className="h-4 w-4 text-accent" />
            </div>
            <div className="text-sm p-3 rounded-lg max-w-[85%] bg-surface-elevated border border-border-subtle text-primary rounded-tl-none flex items-center gap-2">
              <Loader2 className="h-4 w-4 animate-spin text-accent" />
              Analyzing evidence...
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
            onKeyDown={(e) => e.key === 'Enter' && handleSend()}
            placeholder="Ask AI Copilot about this case…"
            disabled={isPending}
            className="flex-1 px-3 py-2 text-xs bg-surface-elevated border border-border-subtle rounded text-primary focus:outline-none focus:border-accent disabled:opacity-50"
          />
          <button
            onClick={handleSend}
            disabled={isPending || !selectedPrompt.trim()}
            className="flex items-center gap-1 px-3.5 py-2 text-xs bg-accent text-white rounded font-medium hover:bg-accent/90 disabled:opacity-50 transition-colors"
          >
            {isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Send className="h-3.5 w-3.5" />}
            Send
          </button>
        </div>
      </div>
    </div>
  );
}
