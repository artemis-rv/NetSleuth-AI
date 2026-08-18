import type { FlowListItem } from '../types';

const PROTOCOL_STYLES: Record<string, string> = {
  tcp: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  udp: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  icmp: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  dns: 'bg-green-500/15 text-green-400 border-green-500/30',
  http: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  tls: 'bg-teal-500/15 text-teal-400 border-teal-500/30',
};

function formatBytes(bytes: number | null): string {
  if (bytes === null) return '—';
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

function formatDuration(sec: number | null): string {
  if (sec === null) return '—';
  if (sec < 1) return `${(sec * 1000).toFixed(0)} ms`;
  return `${sec.toFixed(2)} s`;
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleString('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

interface FlowRowProps {
  flow: FlowListItem;
  onClick: (flow: FlowListItem) => void;
}

export function FlowRow({ flow, onClick }: FlowRowProps) {
  const proto = flow.protocol?.toLowerCase() ?? '';
  const protoStyle = PROTOCOL_STYLES[proto] ?? 'bg-slate-500/15 text-slate-400 border-slate-500/30';

  return (
    <tr
      className="border-b border-border-subtle hover:bg-surface-elevated/50 cursor-pointer transition-colors font-mono text-xs"
      onClick={() => onClick(flow)}
      role="button"
      aria-label={`View flow ${flow.src_ip}:${flow.src_port} → ${flow.dst_ip}:${flow.dst_port}`}
    >
      {/* Timestamp */}
      <td className="px-3 py-2 whitespace-nowrap text-muted">
        {formatTime(flow.timestamp)}
      </td>

      {/* Source */}
      <td className="px-3 py-2 whitespace-nowrap">
        <span className="text-primary">{flow.src_ip}</span>
        <span className="text-muted">:{flow.src_port}</span>
      </td>

      {/* Arrow */}
      <td className="px-1 py-2 text-muted">→</td>

      {/* Destination */}
      <td className="px-3 py-2 whitespace-nowrap">
        <span className="text-primary">{flow.dst_ip}</span>
        <span className="text-muted">:{flow.dst_port}</span>
      </td>

      {/* Protocol */}
      <td className="px-3 py-2 whitespace-nowrap">
        <span className={`inline-flex items-center rounded border px-1.5 py-0.5 text-[10px] font-semibold uppercase ${protoStyle}`}>
          {flow.protocol}
        </span>
      </td>

      {/* Service */}
      <td className="px-3 py-2 whitespace-nowrap text-secondary hidden sm:table-cell">
        {flow.service}
      </td>

      {/* Bytes out → in */}
      <td className="px-3 py-2 whitespace-nowrap text-muted hidden md:table-cell">
        <span className="text-secondary">{formatBytes(flow.orig_bytes)}</span>
        <span className="text-muted mx-1">/</span>
        <span className="text-secondary">{formatBytes(flow.resp_bytes)}</span>
      </td>

      {/* Duration */}
      <td className="px-3 py-2 whitespace-nowrap text-muted hidden lg:table-cell">
        {formatDuration(flow.duration)}
      </td>

      {/* Connection state */}
      <td className="px-3 py-2 whitespace-nowrap">
        {flow.connection_state ? (
          <span className="text-[10px] text-secondary bg-surface-elevated border border-border-subtle rounded px-1.5 py-0.5">
            {flow.connection_state}
          </span>
        ) : (
          <span className="text-muted">—</span>
        )}
      </td>
    </tr>
  );
}
