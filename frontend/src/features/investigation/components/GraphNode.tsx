import { Handle, Position, type NodeProps } from '@xyflow/react';
import { Server, Globe, User, FileText, Cpu, HelpCircle, Activity } from 'lucide-react';

export type GraphNodeData = {
  label: string;
  typeLabel: string;
  riskScore: number | null;
  entityType: string;
  isFocus?: boolean;
};

const ENTITY_ICONS: Record<string, React.ElementType> = {
  ip_address: Globe,
  external_ip: Globe,
  internal_ip: Server,
  host: Server,
  domain: Globe,
  user: User,
  file: FileText,
  hash: FileText,
  process: Activity,
  network: Cpu,
};

function getIcon(entityType: string) {
  const normalized = entityType.toLowerCase();
  return ENTITY_ICONS[normalized] ?? HelpCircle;
}

export function GraphNode({ data, selected }: NodeProps) {
  const { label, typeLabel, riskScore, entityType, isFocus } = data as GraphNodeData;
  const Icon = getIcon(entityType);
  
  const isHighRisk = riskScore !== null && riskScore >= 0.6;
  const isCriticalRisk = riskScore !== null && riskScore >= 0.8;
  
  let riskGlow = '';
  if (isCriticalRisk) {
    riskGlow = 'shadow-[0_0_15px_rgba(239,68,68,0.5)] border-red-500/70';
  } else if (isHighRisk) {
    riskGlow = 'shadow-[0_0_10px_rgba(249,115,22,0.4)] border-orange-500/70';
  } else if (selected || isFocus) {
    riskGlow = 'shadow-[0_0_10px_rgba(59,130,246,0.4)] border-accent';
  } else {
    riskGlow = 'border-border-subtle';
  }

  return (
    <div 
      className={`relative px-4 py-3 min-w-[160px] rounded-lg bg-surface-elevated border-2 transition-all ${riskGlow} ${
        selected ? 'ring-2 ring-accent/50 ring-offset-2 ring-offset-background' : ''
      }`}
    >
      {/* Target handle for incoming connections */}
      <Handle type="target" position={Position.Top} className="!w-2 !h-2 !bg-muted/50 !border-0" />
      
      <div className="flex items-start gap-3">
        <div className={`p-2 rounded-md shrink-0 flex items-center justify-center ${
          isCriticalRisk ? 'bg-red-500/10 text-red-500' : 
          isHighRisk ? 'bg-orange-500/10 text-orange-500' : 
          'bg-accent/10 text-accent'
        }`}>
          <Icon className="w-5 h-5" />
        </div>
        
        <div className="flex flex-col min-w-0">
          <span className="text-sm font-semibold text-primary font-mono truncate max-w-[180px]" title={label}>
            {label}
          </span>
          <span className="text-xs text-muted uppercase tracking-wider font-medium mt-0.5 truncate">
            {typeLabel}
          </span>
        </div>
      </div>
      
      {/* Source handle for outgoing connections */}
      <Handle type="source" position={Position.Bottom} className="!w-2 !h-2 !bg-muted/50 !border-0" />
    </div>
  );
}
