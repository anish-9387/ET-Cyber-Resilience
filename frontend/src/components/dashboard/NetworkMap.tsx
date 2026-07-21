'use client';

import { useCallback, useState, useMemo, useEffect } from 'react';
import ReactFlow, {
  Node,
  Edge,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  NodeMouseHandler,
  MarkerType,
} from 'reactflow';
import 'reactflow/dist/style.css';
import { cn } from '@/lib/utils';
import { api, Asset, AssetGraph, Criticality } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { X, Server, Monitor, Database, Shield, Cloud, Box, HardDrive } from 'lucide-react';

const criticalityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

const iconMap: Record<string, React.ReactNode> = {
  server: <Server className="h-5 w-5" />,
  workstation: <Monitor className="h-5 w-5" />,
  database: <Database className="h-5 w-5" />,
  security_appliance: <Shield className="h-5 w-5" />,
  network_device: <Shield className="h-5 w-5" />,
  cloud_instance: <Cloud className="h-5 w-5" />,
  container: <Box className="h-5 w-5" />,
  storage: <HardDrive className="h-5 w-5" />,
};

interface NetworkNodeData {
  label: string;
  type: string;
  criticality: Criticality;
  ip: string;
  asset: Asset;
}

/**
 * Deterministic layered layout. Assets are grouped into rows by type so the
 * topology is readable without a physics engine; positions are derived from the
 * data, not authored by hand.
 */
function layout(assets: Asset[]): Node<NetworkNodeData>[] {
  const typeOrder = [
    'security_appliance',
    'network_device',
    'server',
    'database',
    'application',
    'virtual_machine',
    'cloud_instance',
    'container',
    'storage',
    'workstation',
    'iot_device',
    'other',
  ];

  const byType = new Map<string, Asset[]>();
  for (const asset of assets) {
    const list = byType.get(asset.asset_type) ?? [];
    list.push(asset);
    byType.set(asset.asset_type, list);
  }

  const rows = typeOrder.filter((t) => byType.has(t));
  for (const t of Array.from(byType.keys())) {
    if (!rows.includes(t)) rows.push(t);
  }

  const nodes: Node<NetworkNodeData>[] = [];
  rows.forEach((type, rowIndex) => {
    const group = byType.get(type)!;
    group.forEach((asset, colIndex) => {
      nodes.push({
        id: asset.id,
        position: {
          x: colIndex * 200 - ((group.length - 1) * 200) / 2,
          y: rowIndex * 130,
        },
        type: 'default',
        data: {
          label: asset.name,
          type: asset.asset_type,
          criticality: asset.criticality,
          ip: asset.ip_address || asset.hostname || '—',
          asset,
        },
      });
    });
  });

  return nodes;
}

function toEdges(graph: AssetGraph): Edge[] {
  return graph.relationships.map((rel) => ({
    id: rel.id,
    source: rel.source_asset_id,
    target: rel.target_asset_id,
    label: rel.label || rel.relationship_type.replace(/_/g, ' '),
    labelStyle: { fill: '#64748b', fontSize: 9 },
    labelBgStyle: { fill: '#111827' },
    style: { stroke: '#334155', strokeWidth: 1.5 },
    markerEnd: { type: MarkerType.ArrowClosed, color: '#334155' },
  }));
}

function NetworkNode({ data }: { data: NetworkNodeData }) {
  const color = criticalityColors[data.criticality] || '#6b7280';
  return (
    <div
      className={cn(
        'flex items-center gap-2 px-3 py-2 rounded-lg border bg-surface-card/90 backdrop-blur-sm shadow-lg min-w-[150px]',
        data.criticality === 'critical' && 'border-accent-red/50',
        data.criticality === 'high' && 'border-accent-orange/40',
        data.criticality === 'medium' && 'border-accent-yellow/30',
        data.criticality === 'low' && 'border-accent-green/20'
      )}
    >
      <div
        className={cn(
          'p-1.5 rounded',
          data.criticality === 'critical'
            ? 'bg-accent-red/20 text-accent-red'
            : 'bg-surface text-gray-400'
        )}
      >
        {iconMap[data.type] || <Box className="h-5 w-5" />}
      </div>
      <div className="min-w-0">
        <p className="text-xs font-medium text-white truncate">{data.label}</p>
        <p className="text-[10px] text-gray-500 font-mono truncate">{data.ip}</p>
      </div>
      <span
        className="ml-auto w-2 h-2 rounded-full shrink-0"
        style={{ backgroundColor: color, boxShadow: `0 0 6px ${color}` }}
      />
    </div>
  );
}

/** Asset topology from GET /digital-twin/graph. */
export function NetworkMap() {
  const state = useApi(() => api.getTwinGraph(), [], 10000);
  const [nodes, setNodes, onNodesChange] = useNodesState<NetworkNodeData>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);
  const [selected, setSelected] = useState<Node<NetworkNodeData> | null>(null);

  useEffect(() => {
    if (!state.data) return;
    setNodes(layout(state.data.nodes));
    setEdges(toEdges(state.data));
  }, [state.data, setNodes, setEdges]);

  const nodeTypes = useMemo(() => ({ default: NetworkNode }), []);

  const onNodeClick: NodeMouseHandler = useCallback((_event, node) => {
    setSelected(node as Node<NetworkNodeData>);
  }, []);

  const isEmpty = state.data !== null && state.data.nodes.length === 0;

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden relative">
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-border">
        <div>
          <h3 className="text-sm font-semibold text-white">Network Topology</h3>
          <p className="text-[10px] text-gray-500 font-mono">
            {state.data
              ? `${state.data.nodes.length} assets · ${state.data.relationships.length} relationships`
              : 'digital-twin/graph'}
          </p>
        </div>
        <div className="flex items-center gap-3">
          {Object.entries(criticalityColors).map(([key, color]) => (
            <div key={key} className="flex items-center gap-1">
              <span
                className="w-1.5 h-1.5 rounded-full"
                style={{ backgroundColor: color }}
              />
              <span className="text-[10px] text-gray-500 capitalize">{key}</span>
            </div>
          ))}
        </div>
      </div>

      {state.initialLoading && <LoadingState label="Loading topology…" />}
      {!state.initialLoading && state.error && (
        <ErrorState error={state.error} onRetry={state.refetch} />
      )}
      {!state.initialLoading && !state.error && isEmpty && (
        <EmptyState
          title="No assets in the graph"
          message="The digital twin has no assets with relationships. Note that /digital-twin/graph only returns assets that participate in at least one relationship."
        />
      )}

      {!state.initialLoading && !state.error && !isEmpty && (
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
              nodeColor={(node) =>
                criticalityColors[(node.data as NetworkNodeData)?.criticality] ||
                '#6b7280'
              }
              maskColor="rgba(10, 14, 23, 0.8)"
              className="bg-surface-card border border-surface-border rounded-lg"
            />
            <Background color="#1e293b" gap={20} />
          </ReactFlow>

          {selected && (
            <div className="absolute top-4 right-4 w-72 bg-surface-card/95 backdrop-blur-md border border-surface-border rounded-xl shadow-2xl z-10">
              <div className="flex items-center justify-between px-4 py-3 border-b border-surface-border">
                <h4 className="text-sm font-semibold text-white truncate">
                  {selected.data.label}
                </h4>
                <button
                  onClick={() => setSelected(null)}
                  className="p-1 text-gray-400 hover:text-white hover:bg-surface-border rounded transition-colors"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="p-4 space-y-2.5">
                {[
                  ['Type', selected.data.asset.asset_type.replace(/_/g, ' ')],
                  ['IP', selected.data.asset.ip_address || '—'],
                  ['Hostname', selected.data.asset.hostname || '—'],
                  ['OS', selected.data.asset.os || '—'],
                  ['Owner', selected.data.asset.owner || '—'],
                  ['Department', selected.data.asset.department || '—'],
                ].map(([label, value]) => (
                  <div key={label} className="flex items-center gap-2">
                    <span className="text-xs text-gray-500 w-20 shrink-0">{label}:</span>
                    <span className="text-xs text-white font-mono truncate">{value}</span>
                  </div>
                ))}
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-500 w-20 shrink-0">Criticality:</span>
                  <span
                    className="text-xs font-medium capitalize"
                    style={{ color: criticalityColors[selected.data.criticality] }}
                  >
                    {selected.data.criticality}
                  </span>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
