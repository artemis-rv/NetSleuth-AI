import { useState, useMemo, useEffect, useCallback } from 'react';
import { 
  ReactFlow, 
  Controls, 
  Background, 
  MiniMap,
  Panel,
  useNodesState,
  useEdgesState,
  type Node, 
  type Edge,
  type NodeMouseHandler,
  type EdgeMouseHandler
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { AlertCircle, Search, Eye, EyeOff, Server, Globe, User, FileText } from 'lucide-react';
import { useGraphQuery } from '../hooks';
import { useFindingsQuery } from '../../findings/hooks';
import type { FindingListItem } from '../../findings/types';
import { Spinner } from '../../../components/ui/Spinner';
import { EmptyState } from '../../../components/feedback/EmptyState';
import { GraphNode, type GraphNodeData } from './GraphNode';
import { getLayoutedElements } from '../utils/graph-layout';

const nodeTypes = {
  custom: GraphNode,
};

interface GraphSectionProps {
  caseId: string;
}

export function GraphSection({ caseId }: GraphSectionProps) {
  const { data: graphData, isLoading, isError, error } = useGraphQuery(caseId);
  const { data: findingsData } = useFindingsQuery(caseId, { page_size: 1000 });

  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);

  // Filters
  const [searchQuery, setSearchQuery] = useState('');
  const [filterType, setFilterType] = useState('ALL');
  const [filterRisk, setFilterRisk] = useState('ALL');
  const [hideUnrelated, setHideUnrelated] = useState(false);

  // Derived filtered nodes
  const filteredEntities = useMemo(() => {
    if (!graphData) return [];
    
    return graphData.nodes.filter(n => {
      // 1. Search filter
      const q = searchQuery.toLowerCase();
      const matchesSearch = !q || 
        n.name.toLowerCase().includes(q) || 
        n.entity_id.toLowerCase().includes(q) ||
        (n.properties && JSON.stringify(n.properties).toLowerCase().includes(q));
        
      // 2. Type filter
      let matchesType = true;
      if (filterType !== 'ALL') {
        const typeGroups: Record<string, string[]> = {
          'HOST': ['host', 'internal_ip'],
          'EXTERNAL': ['external_ip', 'domain'],
          'USER': ['user'],
          'FILE': ['file', 'hash'],
        };
        const group = typeGroups[filterType] || [];
        matchesType = group.includes(n.entity_type.toLowerCase());
      }
      
      // 3. Risk filter
      let matchesRisk = true;
      if (filterRisk !== 'ALL') {
        const risk = n.risk_score || 0;
        if (filterRisk === 'HIGH') matchesRisk = risk >= 0.6;
        else if (filterRisk === 'MEDIUM') matchesRisk = risk >= 0.3 && risk < 0.6;
        else if (filterRisk === 'LOW') matchesRisk = risk < 0.3;
      }
      
      return matchesSearch && matchesType && matchesRisk;
    });
  }, [graphData, searchQuery, filterType, filterRisk]);

  // Derived filtered edges based on node visibility
  const filteredRelationships = useMemo(() => {
    if (!graphData) return [];
    const visibleIds = new Set(filteredEntities.map(n => n.entity_id));
    return graphData.edges.filter(e => visibleIds.has(e.source_entity_id) && visibleIds.has(e.target_entity_id));
  }, [graphData, filteredEntities]);

  // Transform to React Flow
  useEffect(() => {
    if (!graphData) return;
    
    let connectedToSelected = new Set<string>();
    if (selectedNodeId && hideUnrelated) {
      connectedToSelected.add(selectedNodeId);
      graphData.edges.forEach(e => {
        if (e.source_entity_id === selectedNodeId) connectedToSelected.add(e.target_entity_id);
        if (e.target_entity_id === selectedNodeId) connectedToSelected.add(e.source_entity_id);
      });
    }

    const flowNodes: Node[] = filteredEntities.map(entity => {
      const isFocused = entity.entity_id === selectedNodeId;
      const isHidden = Boolean(hideUnrelated && selectedNodeId && !connectedToSelected.has(entity.entity_id));
      
      return {
        id: entity.entity_id,
        type: 'custom',
        position: { x: 0, y: 0 },
        hidden: isHidden ? true : undefined,
        data: {
          label: entity.name,
          typeLabel: entity.entity_type.replace(/_/g, ' '),
          riskScore: entity.risk_score,
          entityType: entity.entity_type,
          isFocus: isFocused
        } as GraphNodeData
      };
    });

    const flowEdges: Edge[] = filteredRelationships.map(rel => {
      const isHidden = Boolean(hideUnrelated && selectedNodeId && 
        rel.source_entity_id !== selectedNodeId && 
        rel.target_entity_id !== selectedNodeId);
        
      const isFocused = rel.relationship_id === selectedEdgeId || 
        rel.source_entity_id === selectedNodeId || 
        rel.target_entity_id === selectedNodeId;

      return {
        id: rel.relationship_id,
        source: rel.source_entity_id,
        target: rel.target_entity_id,
        label: isFocused ? rel.relationship_type.replace(/_/g, ' ') : undefined,
        hidden: isHidden ? true : undefined,
        animated: isFocused,
        style: {
          stroke: isFocused ? '#3b82f6' : '#475569',
          strokeWidth: isFocused ? 2 : 1,
          opacity: isHidden ? 0 : isFocused ? 1 : 0.5,
        },
        labelStyle: { fill: '#94a3b8', fontSize: 10, fontWeight: 500 },
        labelBgStyle: { fill: '#0f172a', opacity: 0.8 },
      };
    });

    // Run auto layout
    const { nodes: layoutedNodes, edges: layoutedEdges } = getLayoutedElements(flowNodes, flowEdges);
    setNodes(layoutedNodes);
    setEdges(layoutedEdges);
    
  }, [graphData, filteredEntities, filteredRelationships, selectedNodeId, selectedEdgeId, hideUnrelated, setNodes, setEdges]);

  const onNodeClick: NodeMouseHandler = useCallback((_, node) => {
    setSelectedNodeId(node.id);
    setSelectedEdgeId(null);
  }, []);

  const onEdgeClick: EdgeMouseHandler = useCallback((_, edge) => {
    setSelectedEdgeId(edge.id);
    setSelectedNodeId(null);
  }, []);

  const onPaneClick = useCallback(() => {
    setSelectedNodeId(null);
    setSelectedEdgeId(null);
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-16">
        <Spinner size={28} />
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex items-center gap-2 p-4 rounded border border-red-500/30 bg-red-500/5 text-red-400 text-sm">
        <AlertCircle className="h-4 w-4 flex-shrink-0" />
        Failed to load attack graph. {(error as Error)?.message}
      </div>
    );
  }

  if (!graphData || graphData.nodes.length === 0) {
    return (
      <EmptyState
        title="No relationships available"
        description="No entity graph has been built for this investigation yet."
      />
    );
  }

  // Derived selected details
  const selectedNode = selectedNodeId ? graphData.nodes.find(n => n.entity_id === selectedNodeId) : null;
  const selectedEdge = selectedEdgeId ? graphData.edges.find(e => e.relationship_id === selectedEdgeId) : null;
  
  // High risk node count
  const highRiskCount = graphData.nodes.filter(n => (n.risk_score || 0) >= 0.6).length;

  return (
    <div className="flex flex-col lg:flex-row gap-4 h-[75vh] min-h-[600px] w-full border border-border-subtle rounded-lg bg-background overflow-hidden relative">
      
      {/* LEFT PANEL - FILTERS */}
      <div className="w-full lg:w-64 flex-shrink-0 border-r border-border-subtle bg-surface-elevated/20 flex flex-col">
        <div className="p-4 border-b border-border-subtle bg-surface">
          <h3 className="text-sm font-semibold uppercase tracking-widest text-muted">Graph Filters</h3>
        </div>
        
        <div className="p-4 space-y-5 overflow-y-auto">
          {/* Search */}
          <div className="space-y-1.5">
            <label htmlFor="search-node" className="text-xs font-semibold text-secondary">Search Node</label>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted" />
              <input 
                id="search-node"
                type="text" 
                placeholder="IP, domain, hash..."
                className="w-full bg-background border border-border-subtle rounded-md pl-8 pr-3 py-1.5 text-xs text-primary focus:border-accent focus:outline-none transition-colors"
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
              />
            </div>
          </div>

          {/* Type Filter */}
          <div className="space-y-1.5">
            <label htmlFor="node-type" className="text-xs font-semibold text-secondary">Node Type</label>
            <select 
              id="node-type"
              className="w-full bg-background border border-border-subtle rounded-md px-3 py-1.5 text-xs text-primary focus:border-accent focus:outline-none"
              value={filterType}
              onChange={e => setFilterType(e.target.value)}
            >
              <option value="ALL">All Types</option>
              <option value="HOST">Internal Hosts</option>
              <option value="EXTERNAL">External IPs & Domains</option>
              <option value="USER">Users</option>
              <option value="FILE">Files & Hashes</option>
            </select>
          </div>

          {/* Risk Filter */}
          <div className="space-y-1.5">
            <label htmlFor="risk-level" className="text-xs font-semibold text-secondary">Risk Level</label>
            <select 
              id="risk-level"
              className="w-full bg-background border border-border-subtle rounded-md px-3 py-1.5 text-xs text-primary focus:border-accent focus:outline-none"
              value={filterRisk}
              onChange={e => setFilterRisk(e.target.value)}
            >
              <option value="ALL">All Levels</option>
              <option value="HIGH">High (≥ 60%)</option>
              <option value="MEDIUM">Medium (30-59%)</option>
              <option value="LOW">Low (&lt; 30%)</option>
            </select>
          </div>
          
          <div className="pt-2 border-t border-border-subtle">
            <button
              onClick={() => {
                setSearchQuery('');
                setFilterType('ALL');
                setFilterRisk('ALL');
                setSelectedNodeId(null);
                setSelectedEdgeId(null);
                setHideUnrelated(false);
              }}
              className="w-full py-1.5 px-3 bg-surface border border-border-subtle rounded text-xs text-secondary hover:text-primary hover:border-accent/50 transition-colors"
            >
              Reset Graph
            </button>
          </div>
        </div>
      </div>

      {/* CENTER - GRAPH CANVAS */}
      <div className="flex-1 relative bg-[#0B1120]">
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          onEdgeClick={onEdgeClick}
          onPaneClick={onPaneClick}
          fitView
          minZoom={0.1}
          maxZoom={1.5}
          className="bg-transparent"
        >
          <Background color="#1e293b" gap={24} size={2} />
          <Controls className="bg-surface border-border-subtle fill-muted" />
          <MiniMap 
            className="bg-surface border-border-subtle" 
            nodeColor="#3b82f6" 
            maskColor="rgba(15, 23, 42, 0.7)"
          />
          
          {/* Header Panel inside Flow */}
          <Panel position="top-left" className="bg-surface-elevated/90 backdrop-blur border border-border-subtle p-3 rounded-lg shadow-xl ml-2 mt-2 flex gap-4">
            <div className="flex flex-col">
              <span className="text-[10px] text-muted uppercase tracking-widest font-semibold mb-0.5">Nodes</span>
              <span className="text-sm font-mono text-primary font-bold">{nodes.length} <span className="text-muted text-xs font-normal">/ {graphData.nodes.length}</span></span>
            </div>
            <div className="w-px bg-border-subtle"></div>
            <div className="flex flex-col">
              <span className="text-[10px] text-muted uppercase tracking-widest font-semibold mb-0.5">Edges</span>
              <span className="text-sm font-mono text-primary font-bold">{edges.length} <span className="text-muted text-xs font-normal">/ {graphData.edges.length}</span></span>
            </div>
            <div className="w-px bg-border-subtle"></div>
            <div className="flex flex-col">
              <span className="text-[10px] text-red-500/80 uppercase tracking-widest font-semibold mb-0.5">High Risk</span>
              <span className="text-sm font-mono text-red-400 font-bold">{highRiskCount}</span>
            </div>
          </Panel>
          
          {/* Legend Panel */}
          <Panel position="bottom-left" className="bg-surface/90 backdrop-blur border border-border-subtle p-3 rounded-lg ml-2 mb-2">
            <h4 className="text-[10px] uppercase tracking-widest text-muted font-semibold mb-2">Legend</h4>
            <div className="grid grid-cols-2 gap-x-4 gap-y-2">
              <div className="flex items-center gap-1.5"><Server className="w-3 h-3 text-muted" /><span className="text-xs text-secondary">Host / IP</span></div>
              <div className="flex items-center gap-1.5"><Globe className="w-3 h-3 text-muted" /><span className="text-xs text-secondary">Domain / Ext</span></div>
              <div className="flex items-center gap-1.5"><User className="w-3 h-3 text-muted" /><span className="text-xs text-secondary">User</span></div>
              <div className="flex items-center gap-1.5"><FileText className="w-3 h-3 text-muted" /><span className="text-xs text-secondary">File / Hash</span></div>
            </div>
          </Panel>
        </ReactFlow>
      </div>

      {/* RIGHT PANEL - DETAILS */}
      {(selectedNode || selectedEdge) && (
        <div className="w-full lg:w-80 flex-shrink-0 border-l border-border-subtle bg-surface-elevated flex flex-col h-full absolute right-0 top-0 lg:relative z-10 animate-in slide-in-from-right-4">
          
          {selectedNode && (
            <>
              <div className="p-4 border-b border-border-subtle bg-surface flex justify-between items-start">
                <div>
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-[10px] font-mono bg-accent/10 text-accent px-1.5 py-0.5 rounded font-semibold uppercase">
                      {selectedNode.entity_type.replace(/_/g, ' ')}
                    </span>
                    {selectedNode.risk_score !== null && (
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded font-semibold ${selectedNode.risk_score >= 0.6 ? 'bg-red-500/10 text-red-500' : 'bg-surface-elevated border border-border-subtle text-secondary'}`}>
                        RISK: {Math.round(selectedNode.risk_score * 100)}%
                      </span>
                    )}
                  </div>
                  <h3 className="text-base font-bold text-primary font-mono break-all">{selectedNode.name}</h3>
                </div>
              </div>

              <div className="flex-1 overflow-y-auto p-4 space-y-6">
                {/* Actions */}
                <div className="flex gap-2">
                  <button 
                    onClick={() => setHideUnrelated(!hideUnrelated)}
                    className="flex-1 flex items-center justify-center gap-1.5 py-1.5 bg-surface border border-border-subtle rounded hover:border-accent transition-colors text-xs text-secondary hover:text-primary"
                  >
                    {hideUnrelated ? <Eye className="w-3.5 h-3.5" /> : <EyeOff className="w-3.5 h-3.5" />}
                    {hideUnrelated ? 'Show All' : 'Focus Node'}
                  </button>
                </div>

                {/* Identity */}
                <div className="space-y-2">
                  <h4 className="text-[11px] font-semibold uppercase tracking-widest text-muted border-b border-border-subtle pb-1">Identity</h4>
                  <div className="text-xs space-y-1.5">
                    <div className="flex justify-between">
                      <span className="text-muted">Canonical ID</span>
                      <span className="text-secondary font-mono truncate max-w-[150px]" title={selectedNode.entity_id}>{selectedNode.entity_id.split('-')[0]}...</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted">First Seen</span>
                      <span className="text-secondary font-mono">{new Date(selectedNode.created_at).toISOString().split('T')[0]}</span>
                    </div>
                  </div>
                </div>

                {/* Properties */}
                {selectedNode.properties && Object.keys(selectedNode.properties).length > 0 && (
                  <div className="space-y-2">
                    <h4 className="text-[11px] font-semibold uppercase tracking-widest text-muted border-b border-border-subtle pb-1">Properties</h4>
                    <div className="bg-surface border border-border-subtle rounded-md p-2">
                      <pre className="text-[10px] text-secondary font-mono whitespace-pre-wrap break-all">
                        {JSON.stringify(selectedNode.properties, null, 2)}
                      </pre>
                    </div>
                  </div>
                )}
                
                {/* Related Findings */}
                {findingsData?.items && (
                  <div className="space-y-2">
                    <h4 className="text-[11px] font-semibold uppercase tracking-widest text-muted border-b border-border-subtle pb-1">Related Findings</h4>
                    <div className="space-y-1.5">
                      {findingsData.items
                        .filter((f: FindingListItem) => JSON.stringify(f).includes(selectedNode.entity_id))
                        .slice(0, 5)
                        .map((f: FindingListItem) => (
                        <div key={f.finding_id} className="text-xs flex items-center justify-between bg-surface border border-border-subtle rounded px-2 py-1.5">
                          <span className="text-secondary truncate">{f.activity.replace(/_/g, ' ')}</span>
                          <span className="text-[10px] text-muted font-mono">{f.finding_id.split('-')[0]}</span>
                        </div>
                      ))}
                      {findingsData.items.filter((f: FindingListItem) => JSON.stringify(f).includes(selectedNode.entity_id)).length === 0 && (
                        <span className="text-xs text-muted italic">No direct findings linked.</span>
                      )}
                    </div>
                  </div>
                )}
              </div>
            </>
          )}

          {selectedEdge && (
            <>
              <div className="p-4 border-b border-border-subtle bg-surface">
                <span className="text-[10px] font-mono bg-accent/10 text-accent px-1.5 py-0.5 rounded font-semibold uppercase mb-2 inline-block">
                  Relationship
                </span>
                <h3 className="text-base font-bold text-primary capitalize">{selectedEdge.relationship_type.replace(/_/g, ' ')}</h3>
              </div>
              
              <div className="flex-1 overflow-y-auto p-4 space-y-6">
                <div className="space-y-2">
                  <h4 className="text-[11px] font-semibold uppercase tracking-widest text-muted border-b border-border-subtle pb-1">Details</h4>
                  <div className="text-xs space-y-2 bg-surface border border-border-subtle rounded p-3">
                    <div className="flex flex-col gap-1">
                      <span className="text-muted">Source</span>
                      <span className="text-primary font-mono break-all">{graphData.nodes.find(n => n.entity_id === selectedEdge.source_entity_id)?.name || selectedEdge.source_entity_id}</span>
                    </div>
                    <div className="w-full flex justify-center py-1 text-muted">
                      ↓
                    </div>
                    <div className="flex flex-col gap-1">
                      <span className="text-muted">Target</span>
                      <span className="text-primary font-mono break-all">{graphData.nodes.find(n => n.entity_id === selectedEdge.target_entity_id)?.name || selectedEdge.target_entity_id}</span>
                    </div>
                  </div>
                </div>

                <div className="space-y-2">
                  <h4 className="text-[11px] font-semibold uppercase tracking-widest text-muted border-b border-border-subtle pb-1">Metadata</h4>
                  <div className="text-xs space-y-1.5">
                    <div className="flex justify-between">
                      <span className="text-muted">Confidence</span>
                      <span className="text-secondary">{selectedEdge.confidence ? `${Math.round(selectedEdge.confidence * 100)}%` : '—'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted">Canonical ID</span>
                      <span className="text-secondary font-mono truncate max-w-[150px]" title={selectedEdge.relationship_id}>{selectedEdge.relationship_id.split('-')[0]}...</span>
                    </div>
                  </div>
                </div>
              </div>
            </>
          )}

        </div>
      )}
    </div>
  );
}
