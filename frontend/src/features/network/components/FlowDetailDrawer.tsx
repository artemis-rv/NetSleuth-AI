import { X, Network, Clock, Database, FileCode, Hash } from 'lucide-react';
import { useFlowDetailQuery, useFlowEventsQuery } from '../hooks';
import { Spinner } from '../../../components/ui/Spinner';

interface FlowDetailDrawerProps {
  flowId: string | null;
  onClose: () => void;
}

function formatBytes(bytes: number | null): string {
  if (bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function Section({ title, icon: Icon, children }: { title: string; icon: any; children: React.ReactNode }) {
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 pb-1 border-b border-border-subtle">
        <Icon className="h-3.5 w-3.5 text-accent" aria-hidden="true" />
        <h3 className="text-xs font-semibold uppercase tracking-widest text-muted">{title}</h3>
      </div>
      {children}
    </div>
  );
}

function KVRow({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 py-1">
      <span className="text-xs text-muted flex-shrink-0 w-36">{label}</span>
      <span className="text-xs text-primary text-right font-mono break-all">{value ?? '—'}</span>
    </div>
  );
}

export function FlowDetailDrawer({ flowId, onClose }: FlowDetailDrawerProps) {
  const { data: flow, isLoading: flowLoading } = useFlowDetailQuery(flowId);
  const { data: events, isLoading: eventsLoading } = useFlowEventsQuery(flowId);

  if (!flowId) return null;

  const isLoading = flowLoading || eventsLoading;

  return (
    <>
      <div
        className="fixed inset-0 bg-black/40 z-40 backdrop-blur-sm"
        onClick={onClose}
        aria-hidden="true"
      />
      <aside
        className="fixed right-0 top-0 h-full w-full max-w-xl bg-surface border-l border-border-subtle z-50 overflow-y-auto shadow-2xl"
        role="dialog"
        aria-modal="true"
        aria-label="Flow detail"
      >
        {/* Header */}
        <div className="sticky top-0 bg-surface border-b border-border-subtle px-6 py-4 flex items-center justify-between z-10">
          <h2 className="text-sm font-semibold text-primary">Flow Detail</h2>
          <button
            onClick={onClose}
            className="rounded p-1 hover:bg-surface-elevated text-muted hover:text-primary transition-colors"
            aria-label="Close flow detail"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-6">
          {isLoading && (
            <div className="flex items-center justify-center py-16">
              <Spinner size={28} />
            </div>
          )}

          {flow && (
            <>
              {/* Connection */}
              <Section title="Connection" icon={Network}>
                <div className="flex items-center gap-3 py-2 font-mono text-sm">
                  <div className="text-center">
                    <p className="text-primary font-semibold">{flow.src_ip}</p>
                    <p className="text-muted text-xs">:{flow.src_port}</p>
                  </div>
                  <div className="flex-1 border-t border-dashed border-border-subtle relative">
                    <span className="absolute left-1/2 -translate-x-1/2 -top-2.5 text-[10px] bg-surface text-accent px-1.5">
                      {flow.protocol}
                    </span>
                  </div>
                  <div className="text-center">
                    <p className="text-primary font-semibold">{flow.dst_ip}</p>
                    <p className="text-muted text-xs">:{flow.dst_port}</p>
                  </div>
                </div>
                <KVRow label="Service" value={flow.service} />
                <KVRow label="Connection State" value={flow.connection_state} />
                <KVRow label="Zeek UID" value={flow.zeek_uid} />
              </Section>

              {/* Timing */}
              <Section title="Timing" icon={Clock}>
                <KVRow label="Timestamp" value={new Date(flow.timestamp).toLocaleString()} />
                {flow.start_time && (
                  <KVRow label="Start" value={new Date(flow.start_time).toLocaleString()} />
                )}
                {flow.end_time && (
                  <KVRow label="End" value={new Date(flow.end_time).toLocaleString()} />
                )}
                {flow.duration !== null && (
                  <KVRow label="Duration" value={`${flow.duration?.toFixed(3)} s`} />
                )}
              </Section>

              {/* Traffic */}
              <Section title="Traffic" icon={Database}>
                <KVRow label="Orig → Resp bytes" value={`${formatBytes(flow.orig_bytes)} / ${formatBytes(flow.resp_bytes)}`} />
                <KVRow label="Orig → Resp packets" value={
                  flow.orig_packets !== null
                    ? `${flow.orig_packets} / ${flow.resp_packets ?? '—'}`
                    : '—'
                } />
              </Section>

              {/* PCAP references */}
              {(flow.pcap_frame_start !== null || flow.pcap_byte_offset !== null) && (
                <Section title="PCAP Reference" icon={Hash}>
                  {flow.pcap_frame_start !== null && (
                    <KVRow label="Frame range" value={`${flow.pcap_frame_start} – ${flow.pcap_frame_end ?? '?'}`} />
                  )}
                  {flow.pcap_byte_offset !== null && (
                    <KVRow label="Byte offset" value={flow.pcap_byte_offset} />
                  )}
                </Section>
              )}

              {/* Protocol Events */}
              {events && events.items.length > 0 && (
                <Section title={`Protocol Events (${events.items.length})`} icon={FileCode}>
                  <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                    {events.items.map((evt) => (
                      <div
                        key={evt.event_id}
                        className="rounded border border-border-subtle p-3 space-y-1.5"
                      >
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-medium text-accent font-mono">{evt.protocol}</span>
                          <span className="text-xs text-muted tabular-nums">
                            {new Date(evt.timestamp).toLocaleTimeString()}
                          </span>
                        </div>
                        {Object.entries(evt.protocol_data).slice(0, 8).map(([k, v]) => (
                          <div key={k} className="flex justify-between gap-3 text-xs">
                            <span className="text-muted font-mono flex-shrink-0">{k}</span>
                            <span className="text-secondary text-right break-all font-mono">
                              {String(v)}
                            </span>
                          </div>
                        ))}
                      </div>
                    ))}
                  </div>
                </Section>
              )}
            </>
          )}
        </div>
      </aside>
    </>
  );
}
