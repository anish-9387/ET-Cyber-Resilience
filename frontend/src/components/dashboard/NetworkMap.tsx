'use client';

import { useCallback, useState, useMemo } from 'react';
import ReactFlow, {
  Node,
  Edge,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  NodeMouseHandler,
  Panel,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { cn } from '@/lib/utils';
import { X, Server, Monitor, Users, Shield } from 'lucide-react';

const statusColors: Record<string, string> = {
  healthy: '#22c55e',
  degraded: '#eab308',
  compromised: '#ef4444',
  recovering: '#06b6d4',
};

const iconMap: Record<string, React.ReactNode> = {
  server: <Server className="h-5 w-5" />,
  workstation: <Monitor className="h-5 w-5" />,
  user: <Users className="h-5 w-5" />,
  firewall: <Shield className="h-5 w-5" />,
};

interface NetworkNodeData {
  label: string;
  type: string;
  status: string;
  ip: string;
  risk: number;
}

const initialNodes: Node<NetworkNodeData>[] = [
  { id: 'fw-1', position: { x: 350, y: 0 }, data: { label: 'Firewall', type: 'firewall', status: 'healthy', ip: '10.0.0.1', risk: 0 }, type: 'default' },
  { id: 'dc-1', position: { x: 100, y: 150 }, data: { label: 'DC-01', type: 'server', status: 'compromised', ip: '10.0.1.10', risk: 92 }, type: 'default' },
  { id: 'sql-1', position: { x: 350, y: 150 }, data: { label: 'SQL-01', type: 'server', status: 'degraded', ip: '10.0.1.20', risk: 65 }, type: 'default' },
  { id: 'web-1', position: { x: 600, y: 150 }, data: { label: 'WEB-01', type: 'server', status: 'healthy', ip: '10.0.1.30', risk: 15 }, type: 'default' },
  { id: 'ws-1', position: { x: 100, y: 320 }, data: { label: 'WS-12', type: 'workstation', status: 'compromised', ip: '10.0.2.12', risk: 88 }, type: 'default' },
  { id: 'ws-2', position: { x: 350, y: 320 }, data: { label: 'WS-08', type: 'workstation', status: 'degraded', ip: '10.0.2.8', risk: 45 }, type: 'default' },
  { id: 'ws-3', position: { x: 600, y: 320 }, data: { label: 'WS-15', type: 'workstation', status: 'healthy', ip: '10.0.2.15', risk: 10 }, type: 'default' },
  { id: 'user-1', position: { x: 200, y: 470 }, data: { label: 'jdoe@acme', type: 'user', status: 'healthy', ip: '-', risk: 30 }, type: 'default' },
  { id: 'user-2', position: { x: 500, y: 470 }, data: { label: 'asmith@acme', type: 'user', status: 'healthy', ip: '-', risk: 20 }, type: 'default' },
];

const initialEdges: Edge[] = [
  { id: 'e-fw-dc', source: 'fw-1', target: 'dc-1', animated: true, style: { stroke: '#ef4444', strokeWidth: 2 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#ef4444' } },
  { id: 'e-fw-sql', source: 'fw-1', target: 'sql-1', style: { stroke: '#eab308', strokeWidth: 1.5 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#eab308' } },
  { id: 'e-fw-web', source: 'fw-1', target: 'web-1', style: { stroke: '#22c55e', strokeWidth: 1.5 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#22c55e' } },
  { id: 'e-dc-ws1', source: 'dc-1', target: 'ws-1', animated: true, style: { stroke: '#ef4444', strokeWidth: 2, strokeDasharray: '5 5' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#ef4444' } },
  { id: 'e-dc-ws2', source: 'dc-1', target: 'ws-2', animated: true, style: { stroke: '#f97316', strokeWidth: 1.5, strokeDasharray: '5 5' }, markerEnd: { type: MarkerType.ArrowClosed, color: '#f97316' } },
  { id: 'e-sql-ws2', source: 'sql-1', target: 'ws-2', style: { stroke: '#eab308', strokeWidth: 1 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#eab308' } },
  { id: 'e-web-ws3', source: 'web-1', target: 'ws-3', style: { stroke: '#22c55e', strokeWidth: 1 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#22c55e' } },
  { id: 'e-ws1-u1', source: 'ws-1', target: 'user-1', style: { stroke: '#06b6d4', strokeWidth: 1 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#06b6d4' } },
  { id: 'e-ws3-u2', source: 'ws-3', target: 'user-2', style: { stroke: '#22c55e', strokeWidth: 1 }, markerEnd: { type: MarkerType.ArrowClosed, color: '#22c55e' } },
];

function NetworkNode({ data }: { data: NetworkNodeData }) {
  const statusColor = statusColors[data.status] || '#6b7280';
  return (
    <div
      className={cn(
        'flex items-center gap-2 px-3 py-2 rounded-lg border bg-surface-card/90 backdrop-blur-sm shadow-lg min-w-[140px] transition-all duration-200 hover:scale-105',
        data.status === 'compromised' && 'border-accent-red/50 shadow-glow-red',
        data.status === 'degraded' && 'border-accent-yellow/30',
        data.status === 'healthy' && 'border-accent-green/20',
        data.status === 'recovering' && 'border-accent-cyan/30',
      )}
    >
      <div className={cn('p-1.5 rounded', data.status === 'compromised' ? 'bg-accent-red/20 text-accent-red' : 'bg-surface text-gray-400')}>
        {iconMap[data.type]}
      </div>
      <div className="min-w-0">
        <p className="text-xs font-medium text-white truncate">{data.label}</p>
        <p className="text-[10px] text-gray-500 font-mono">{data.ip}</p>
      </div>
      <div className="ml-auto flex items-center gap-1">
        <span
          className="w-2 h-2 rounded-full animate-pulse"
          style={{ backgroundColor: statusColor, boxShadow: `0 0 6px ${statusColor}` }}
        />
      </div>
    </div>
  );
}

export function NetworkMap() {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);
  const [selected, setSelected] = useState<Node<NetworkNodeData> | null>(null);

  const nodeTypes = useMemo(() => ({ default: NetworkNode }), []);

  const onNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    setSelected(node as Node<NetworkNodeData>);
  }, []);

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden relative">
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-border">
        <h3 className="text-sm font-semibold text-white">Network Topology</h3>
        <div className="flex items-center gap-3">
          {Object.entries(statusColors).map(([key, color]) => (
            <div key={key} className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
              <span className="text-[10px] text-gray-500 capitalize">{key}</span>
            </div>
          ))}
        </div>
      </div>
      <div className="relative" style={{ height: 500 }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onNodeClick={onNodeClick}
          nodeTypes={nodeTypes as any}
          fitView
          attributionPosition="bottom-left"
          className="bg-surface"
        >
          <Controls className="bg-surface-card border-surface-border" />
          <MiniMap
            nodeColor={(node) => statusColors[(node.data as NetworkNodeData)?.status] || '#6b7280'}
            maskColor="rgba(10, 14, 23, 0.8)"
            className="bg-surface-card border border-surface-border rounded-lg"
          />
          <Background color="#1e293b" gap={20} />
        </ReactFlow>

        {/* Detail Panel */}
        {selected && (
          <div className="absolute top-4 right-4 w-72 bg-surface-card/95 backdrop-blur-md border border-surface-border rounded-xl shadow-2xl z-10">
            <div className="flex items-center justify-between px-4 py-3 border-b border-surface-border">
              <h4 className="text-sm font-semibold text-white">{selected.data.label}</h4>
              <button
                onClick={() => setSelected(null)}
                className="p-1 text-gray-400 hover:text-white hover:bg-surface-border rounded transition-colors"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
            <div className="p-4 space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-500">Type:</span>
                <span className="text-xs text-white font-medium capitalize">{selected.data.type}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-500">IP:</span>
                <span className="text-xs text-white font-mono">{selected.data.ip}</span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-500">Status:</span>
                <span
                  className={cn(
                    'text-xs font-medium capitalize',
                    selected.data.status === 'compromised' && 'text-accent-red',
                    selected.data.status === 'degraded' && 'text-accent-yellow',
                    selected.data.status === 'healthy' && 'text-accent-green',
                  )}
                >
                  {selected.data.status}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-xs text-gray-500">Risk Score:</span>
                <div className="flex-1 h-1.5 bg-surface rounded-full overflow-hidden">
                  <div
                    className={cn(
                      'h-full rounded-full transition-all',
                      selected.data.risk > 70 ? 'bg-accent-red' : selected.data.risk > 40 ? 'bg-accent-yellow' : 'bg-accent-green'
                    )}
                    style={{ width: `${selected.data.risk}%` }}
                  />
                </div>
                <span className="text-xs text-white font-mono">{selected.data.risk}%</span>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
