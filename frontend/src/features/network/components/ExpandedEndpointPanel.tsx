import { useState } from 'react';
import { 
  Server, Globe, ShieldAlert, ArrowUpRight, ArrowDownLeft, 
  Activity, Link as LinkIcon 
} from 'lucide-react';
import type { NetworkEndpointContext } from '../types';

interface ExpandedEndpointPanelProps {
  endpoint: NetworkEndpointContext;
  onSelectFlow: (flowId: string) => void;
  onSelectFinding: (findingId: string) => void;
}

export function ExpandedEndpointPanel({ endpoint, onSelectFlow, onSelectFinding }: ExpandedEndpointPanelProps) {
  const [activeTab, setActiveTab] = useState<
    'OVERVIEW' | 'COMMUNICATION' | 'TRAFFIC' | 'PROTOCOLS' | 'ARTIFACTS' | 'FINDINGS' | 'TIMELINE' | 'EVIDENCE'
  >('OVERVIEW');

  function formatBytes(bytes: number): string {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
  }

  const isPrivate = endpoint.network_scope === 'PRIVATE/INTERNAL';

  return (
    <div className="border-t border-border-subtle bg-background p-4 space-y-4">
      {/* 8-Section Navigation Tabs */}
      <div className="flex items-center gap-1 border-b border-border-subtle pb-2 overflow-x-auto text-xs font-mono">
        <button
          onClick={() => setActiveTab('OVERVIEW')}
          className={`px-3 py-1.5 rounded transition-colors ${activeTab === 'OVERVIEW' ? 'bg-accent/20 text-accent font-semibold border border-accent/30' : 'text-muted hover:text-primary'}`}
        >
          1. Overview
        </button>
        <button
          onClick={() => setActiveTab('COMMUNICATION')}
          className={`px-3 py-1.5 rounded transition-colors ${activeTab === 'COMMUNICATION' ? 'bg-accent/20 text-accent font-semibold border border-accent/30' : 'text-muted hover:text-primary'}`}
        >
          2. Communication ({endpoint.communication.total_flows})
        </button>
        <button
          onClick={() => setActiveTab('TRAFFIC')}
          className={`px-3 py-1.5 rounded transition-colors ${activeTab === 'TRAFFIC' ? 'bg-accent/20 text-accent font-semibold border border-accent/30' : 'text-muted hover:text-primary'}`}
        >
          3. Traffic ({formatBytes(endpoint.traffic.total_bytes)})
        </button>
        <button
          onClick={() => setActiveTab('PROTOCOLS')}
          className={`px-3 py-1.5 rounded transition-colors ${activeTab === 'PROTOCOLS' ? 'bg-accent/20 text-accent font-semibold border border-accent/30' : 'text-muted hover:text-primary'}`}
        >
          4. Protocols ({endpoint.communication.protocols.join(', ') || 'N/A'})
        </button>
        <button
          onClick={() => setActiveTab('ARTIFACTS')}
          className={`px-3 py-1.5 rounded transition-colors ${activeTab === 'ARTIFACTS' ? 'bg-accent/20 text-accent font-semibold border border-accent/30' : 'text-muted hover:text-primary'}`}
        >
          5. Artifacts ({endpoint.artifacts.length})
        </button>
        <button
          onClick={() => setActiveTab('FINDINGS')}
          className={`px-3 py-1.5 rounded transition-colors ${activeTab === 'FINDINGS' ? 'bg-accent/20 text-accent font-semibold border border-accent/30' : 'text-muted hover:text-primary'}`}
        >
          6. M2 Findings ({endpoint.m2_findings.finding_count})
        </button>
        <button
          onClick={() => setActiveTab('TIMELINE')}
          className={`px-3 py-1.5 rounded transition-colors ${activeTab === 'TIMELINE' ? 'bg-accent/20 text-accent font-semibold border border-accent/30' : 'text-muted hover:text-primary'}`}
        >
          7. Timeline
        </button>
        <button
          onClick={() => setActiveTab('EVIDENCE')}
          className={`px-3 py-1.5 rounded transition-colors ${activeTab === 'EVIDENCE' ? 'bg-accent/20 text-accent font-semibold border border-accent/30' : 'text-muted hover:text-primary'}`}
        >
          8. PCAP Traceability
        </button>
      </div>

      {/* TAB CONTENT */}
      {/* 1. OVERVIEW */}
      {activeTab === 'OVERVIEW' && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs">
          <div className="bg-surface p-3 rounded border border-border-subtle space-y-2">
            <span className="text-muted text-[10px] uppercase font-semibold tracking-wider block">Endpoint Identity</span>
            <div className="flex items-center gap-2">
              {isPrivate ? <Server className="h-4 w-4 text-emerald-400" /> : <Globe className="h-4 w-4 text-amber-400" />}
              <span className="font-mono text-sm font-bold text-primary">{endpoint.ip}</span>
            </div>
            <p className="text-muted">IPv{endpoint.ip_version} · {endpoint.network_scope} · Role: {endpoint.role}</p>
            {endpoint.hostname && <p className="font-mono text-accent">Hostname: {endpoint.hostname}</p>}
            {endpoint.associated_domain && <p className="font-mono text-secondary">Domain: {endpoint.associated_domain}</p>}
          </div>

          <div className="bg-surface p-3 rounded border border-border-subtle space-y-2">
            <span className="text-muted text-[10px] uppercase font-semibold tracking-wider block">M2 Threat Assessment</span>
            {endpoint.m2_findings.finding_count > 0 ? (
              <div className="space-y-1">
                <div className="flex items-center gap-2">
                  <ShieldAlert className="h-4 w-4 text-red-400" />
                  <span className="font-bold text-red-400">{endpoint.m2_findings.highest_severity} SEVERITY</span>
                </div>
                <p className="font-mono text-muted">Risk Score: {(endpoint.m2_findings.max_risk_score * 100).toFixed(0)}%</p>
                <p className="font-mono text-muted">Anomaly Score: {(endpoint.m2_findings.max_anomaly_score * 100).toFixed(0)}%</p>
                <p className="font-mono text-muted">Activities: {endpoint.m2_findings.activity_classes.join(', ')}</p>
              </div>
            ) : (
              <p className="text-muted italic">No suspicious findings associated with this endpoint.</p>
            )}
          </div>

          <div className="bg-surface p-3 rounded border border-border-subtle space-y-2">
            <span className="text-muted text-[10px] uppercase font-semibold tracking-wider block">Temporal Bounds</span>
            {endpoint.temporal.first_seen ? (
              <div className="space-y-1 font-mono text-muted">
                <p>First Seen: {new Date(endpoint.temporal.first_seen).toLocaleTimeString()}</p>
                <p>Last Seen: {new Date(endpoint.temporal.last_seen || endpoint.temporal.first_seen).toLocaleTimeString()}</p>
                <p>Active Duration: {endpoint.temporal.active_duration_seconds.toFixed(1)}s</p>
                <p>Connection Frequency: {endpoint.temporal.connection_rate_per_min.toFixed(1)} / min</p>
              </div>
            ) : (
              <p className="text-muted italic font-mono">No timestamp data available</p>
            )}
          </div>
        </div>
      )}

      {/* 2. COMMUNICATION */}
      {activeTab === 'COMMUNICATION' && (
        <div className="space-y-3 text-xs">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-2">
            <div className="bg-surface p-2.5 rounded border border-border-subtle">
              <span className="text-muted text-[10px] uppercase font-semibold">Total Flows</span>
              <p className="font-mono text-base font-bold text-primary">{endpoint.communication.total_flows}</p>
            </div>
            <div className="bg-surface p-2.5 rounded border border-border-subtle">
              <span className="text-muted text-[10px] uppercase font-semibold">Destination Ports</span>
              <p className="font-mono text-secondary truncate">{endpoint.communication.destination_ports.join(', ') || 'None'}</p>
            </div>
            <div className="bg-surface p-2.5 rounded border border-border-subtle">
              <span className="text-muted text-[10px] uppercase font-semibold">Protocols / Services</span>
              <p className="font-mono text-accent truncate">{endpoint.communication.protocols.join(', ')} / {endpoint.communication.services.join(', ')}</p>
            </div>
            <div className="bg-surface p-2.5 rounded border border-border-subtle">
              <span className="text-muted text-[10px] uppercase font-semibold">Connection States</span>
              <p className="font-mono text-muted truncate">{endpoint.communication.connection_states.join(', ') || 'N/A'}</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3 font-mono">
            <div className="bg-surface p-3 rounded border border-border-subtle">
              <span className="text-muted text-[10px] uppercase font-semibold block mb-1">Unique Sources ({endpoint.communication.unique_sources.length})</span>
              <div className="max-h-32 overflow-y-auto space-y-1 text-muted">
                {endpoint.communication.unique_sources.map(ip => (
                  <p key={ip}>{ip}</p>
                ))}
              </div>
            </div>
            <div className="bg-surface p-3 rounded border border-border-subtle">
              <span className="text-muted text-[10px] uppercase font-semibold block mb-1">Unique Destinations ({endpoint.communication.unique_destinations.length})</span>
              <div className="max-h-32 overflow-y-auto space-y-1 text-muted">
                {endpoint.communication.unique_destinations.map(ip => (
                  <p key={ip}>{ip}</p>
                ))}
              </div>
            </div>
          </div>
        </div>
      )}

      {/* 3. TRAFFIC */}
      {activeTab === 'TRAFFIC' && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-xs font-mono">
          <div className="bg-surface p-3 rounded border border-border-subtle flex items-center gap-3">
            <ArrowUpRight className="h-6 w-6 text-emerald-400 flex-shrink-0" />
            <div>
              <span className="text-muted text-[10px] uppercase font-semibold">OUTBOUND DATA</span>
              <p className="text-base font-bold text-emerald-400">{formatBytes(endpoint.traffic.bytes_sent)}</p>
              <p className="text-muted text-[11px]">{endpoint.traffic.packets_sent} packets</p>
            </div>
          </div>

          <div className="bg-surface p-3 rounded border border-border-subtle flex items-center gap-3">
            <ArrowDownLeft className="h-6 w-6 text-amber-400 flex-shrink-0" />
            <div>
              <span className="text-muted text-[10px] uppercase font-semibold">INBOUND DATA</span>
              <p className="text-base font-bold text-amber-400">{formatBytes(endpoint.traffic.bytes_received)}</p>
              <p className="text-muted text-[11px]">{endpoint.traffic.packets_received} packets</p>
            </div>
          </div>

          <div className="bg-surface p-3 rounded border border-border-subtle flex items-center gap-3">
            <Activity className="h-6 w-6 text-accent flex-shrink-0" />
            <div>
              <span className="text-muted text-[10px] uppercase font-semibold">TOTAL TRAFFIC VOLUME</span>
              <p className="text-base font-bold text-primary">{formatBytes(endpoint.traffic.total_bytes)}</p>
              <p className="text-muted text-[11px]">Avg Flow Duration: {endpoint.traffic.avg_flow_duration.toFixed(2)}s</p>
            </div>
          </div>
        </div>
      )}

      {/* 4. PROTOCOLS */}
      {activeTab === 'PROTOCOLS' && (
        <div className="space-y-3 text-xs">
          <div className="bg-surface p-3 rounded border border-border-subtle space-y-1">
            <span className="font-semibold text-accent uppercase tracking-wider block">DNS Protocol Activity ({endpoint.protocol_activity.dns.query_count} queries)</span>
            {endpoint.protocol_activity.dns.unique_queries.length > 0 ? (
              <div className="font-mono text-muted space-y-1">
                <p>Queries: {endpoint.protocol_activity.dns.unique_queries.join(', ')}</p>
              </div>
            ) : (
              <p className="text-muted italic">No DNS query records observed for this endpoint.</p>
            )}
          </div>

          <div className="bg-surface p-3 rounded border border-border-subtle space-y-1">
            <span className="font-semibold text-accent uppercase tracking-wider block">HTTP Protocol Activity ({endpoint.protocol_activity.http.request_count} requests)</span>
            {endpoint.protocol_activity.http.request_count > 0 ? (
              <div className="font-mono text-muted space-y-1">
                <p>Methods: {endpoint.protocol_activity.http.methods.join(', ') || 'GET'}</p>
                <p>Hosts: {endpoint.protocol_activity.http.hosts.join(', ') || 'N/A'}</p>
                <p>URIs: {endpoint.protocol_activity.http.uris.join(', ') || 'N/A'}</p>
                <p>User Agents: {endpoint.protocol_activity.http.user_agents.join(', ') || 'N/A'}</p>
              </div>
            ) : (
              <p className="text-muted italic">No HTTP application transactions observed for this endpoint.</p>
            )}
          </div>

          <div className="bg-surface p-3 rounded border border-border-subtle space-y-1">
            <span className="font-semibold text-accent uppercase tracking-wider block">TLS / SSL Activity ({endpoint.protocol_activity.tls.session_count} sessions)</span>
            {endpoint.protocol_activity.tls.session_count > 0 ? (
              <div className="font-mono text-muted space-y-1">
                <p>Server Name Indication (SNI): {endpoint.protocol_activity.tls.server_names.join(', ') || 'N/A'}</p>
                <p>TLS Versions: {endpoint.protocol_activity.tls.versions.join(', ') || 'TLS 1.2 / TLS 1.3'}</p>
              </div>
            ) : (
              <p className="text-muted italic">No TLS handshake metadata observed for this endpoint.</p>
            )}
          </div>
        </div>
      )}

      {/* 5. ARTIFACTS */}
      {activeTab === 'ARTIFACTS' && (
        <div className="space-y-2 text-xs">
          {endpoint.artifacts.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              {endpoint.artifacts.map((art) => (
                <div key={art.artifact_id} className="bg-surface p-2.5 rounded border border-border-subtle flex items-center justify-between">
                  <div>
                    <span className="text-[10px] uppercase font-bold text-accent px-1.5 py-0.5 bg-accent/10 rounded mr-2">{art.type}</span>
                    <span className="font-mono text-primary font-medium">{art.value}</span>
                  </div>
                  {art.flow_id && (
                    <button
                      onClick={() => onSelectFlow(art.flow_id!)}
                      className="text-[10px] text-accent hover:underline flex items-center gap-1 font-mono"
                    >
                      <LinkIcon className="h-3 w-3" /> Pivot Flow
                    </button>
                  )}
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted italic text-xs">No extracted artifacts associated with this endpoint.</p>
          )}
        </div>
      )}

      {/* 6. FINDINGS */}
      {activeTab === 'FINDINGS' && (
        <div className="space-y-2 text-xs">
          {endpoint.m2_findings.items.length > 0 ? (
            <div className="space-y-2">
              {endpoint.m2_findings.items.map((item) => (
                <div 
                  key={item.finding_id} 
                  onClick={() => onSelectFinding(item.finding_id)}
                  className="bg-surface p-3 rounded border border-red-500/30 hover:border-red-500/60 transition-colors cursor-pointer space-y-1"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <ShieldAlert className="h-4 w-4 text-red-400" />
                      <span className="font-bold text-red-400 uppercase">{item.activity}</span>
                      <span className="text-[10px] font-mono px-1.5 py-0.5 bg-red-500/10 border border-red-500/30 rounded text-red-300">
                        {item.severity}
                      </span>
                    </div>
                    <span className="font-mono text-muted text-[11px]">Risk: {(item.risk_score * 100).toFixed(0)}%</span>
                  </div>
                  <p className="text-secondary text-[11px] font-mono">{item.rationale}</p>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-muted italic text-xs">No M2 findings associated with this endpoint.</p>
          )}
        </div>
      )}

      {/* 7. TIMELINE */}
      {activeTab === 'TIMELINE' && (
        <div className="space-y-2 text-xs font-mono">
          <p className="text-muted text-[11px] mb-2">Endpoint-specific activity sequence from M1 flow telemetry:</p>
          <div className="border-l-2 border-accent/40 pl-3 space-y-3">
            {endpoint.temporal.first_seen ? (
              <>
                <div className="relative">
                  <span className="absolute -left-[17px] top-1 h-2 w-2 rounded-full bg-accent" />
                  <p className="text-accent font-bold">{new Date(endpoint.temporal.first_seen).toLocaleTimeString()}</p>
                  <p className="text-primary">First communication flow recorded ({endpoint.communication.protocols.join(', ')})</p>
                </div>
                {endpoint.temporal.last_seen && endpoint.temporal.last_seen !== endpoint.temporal.first_seen && (
                  <div className="relative">
                    <span className="absolute -left-[17px] top-1 h-2 w-2 rounded-full bg-accent" />
                    <p className="text-accent font-bold">{new Date(endpoint.temporal.last_seen).toLocaleTimeString()}</p>
                    <p className="text-primary">Last active communication session ({endpoint.communication.total_flows} total flows)</p>
                  </div>
                )}
              </>
            ) : (
              <p className="text-muted italic">No temporal events recorded.</p>
            )}
          </div>
        </div>
      )}

      {/* 8. PCAP TRACEABILITY */}
      {activeTab === 'EVIDENCE' && (
        <div className="space-y-3 text-xs font-mono">
          <div className="flex items-center justify-between bg-surface p-2.5 rounded border border-border-subtle">
            <span className="text-muted font-medium">Original Packet Traceability</span>
            {endpoint.evidence.has_packet_references ? (
              <span className="text-emerald-400 font-bold bg-emerald-500/10 px-2 py-0.5 rounded border border-emerald-500/30">
                Frame & Byte Offsets Available
              </span>
            ) : (
              <span className="text-amber-400 font-bold bg-amber-500/10 px-2 py-0.5 rounded border border-amber-500/30">
                Packet-level reference unavailable
              </span>
            )}
          </div>

          <div className="space-y-2 max-h-48 overflow-y-auto">
            {endpoint.evidence.traceability_items.map((item) => (
              <div key={item.flow_id} className="bg-surface p-2.5 rounded border border-border-subtle flex items-center justify-between">
                <div>
                  <p className="text-primary font-bold">Zeek UID: {item.zeek_uid}</p>
                  <p className="text-muted text-[11px]">Acquisition ID: {item.acquisition_id}</p>
                </div>
                <div>
                  {item.has_packet_reference ? (
                    <div className="text-right text-emerald-400 text-[11px]">
                      <p>Frames: {item.pcap_frame_start} — {item.pcap_frame_end}</p>
                      <p>Byte Offset: {item.pcap_byte_offset}</p>
                    </div>
                  ) : (
                    <span className="text-muted italic text-[11px]">No exact PCAP frame offset</span>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
