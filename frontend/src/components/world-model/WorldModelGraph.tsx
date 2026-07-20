'use client';

import { useCallback, useEffect, useMemo, useState } from 'react';
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
import { WorldModelGraph as GraphData, WorldModelGraphNode } from '@/lib/api';

/**
 * Colour encodes P(compromised): green -> yellow -> orange -> red.
 * Size encodes P(compromised) too (higher probability = larger node).
 * Border opacity/style encodes confidence: a dashed, faint border means the
 * model is uncertain even if the probability is high.
 */
export function compromiseColor(p: number): string {
  if (p >= 0.8) return '#ef4444';
  if (p >= 0.5) return '#f97316';
  if (p >= 0.2) return '#eab308';
  return '#22c55e';
}

interface NodeData extends WorldModelGraphNode {
  onSelect: (id: string) => void;
  selected: boolean;
}

function BeliefNode({ data }: { data: NodeData }) {
  const color = compromiseColor(data.p_compromised);
  const pct = Math.round(data.p_compromised * 100);
  const confidencePct = Math.round(data.confidence * 100);

  // Size scales with belief: 56px at p=0 up to 92px at p=1.
  const size = 56 + data.p_compromised * 36;
  // Low confidence renders a dashed, translucent border.
  const lowConfidence = data.confidence < 0.4;

  return (
    <div className="flex flex-col items-center gap-1">
      <div
        className={cn(
          'rounded-full flex flex-col items-center justify-center transition-all duration-500 backdrop-blur-sm',
          data.selected && 'ring-2 ring-accent-cyan ring-offset-2 ring-offset-surface'
        )}
        style={{
          width: size,
          height: size,
          backgroundColor: `${color}22`,
          border: `${lowConfidence ? '2px dashed' : '3px solid'} ${color}${
            lowConfidence ? '66' : 'ff'
          }`,
          boxShadow:
            data.p_compromised >= 0.5 ? `0 0 16px ${color}55` : undefined,
        }}
        title={`${data.label} — P(compromised) ${pct}%, confidence ${confidencePct}%`}
      >
        <span className="text-[11px] font-bold font-mono" style={{ color }}>
          {pct}%
        </span>
        <span className="text-[8px] text-gray-400 font-mono">±{100 - confidencePct}</span>
      </div>
      <div className="text-center max-w-[110px]">
        <p className="text-[10px] font-medium text-white truncate">{data.label}</p>
        <p className="text-[8px] text-gray-500 font-mono truncate">{data.type}</p>
      </div>
    </div>
  );
}

/** Radial layout keyed off entity type so the graph is stable across polls. */
function layout(nodes: WorldModelGraphNode[]): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>();
  const byType = new Map<string, WorldModelGraphNode[]>();

  for (const node of nodes) {
    const list = byType.get(node.type) ?? [];
    list.push(node);
    byType.set(node.type, list);
  }

  const types = Array.from(byType.keys()).sort();
  types.forEach((type, rowIndex) => {
    const group = byType.get(type)!;
    group
      .slice()
      .sort((a, b) => a.id.localeCompare(b.id))
      .forEach((node, colIndex) => {
        positions.set(node.id, {
          x: colIndex * 190 - ((group.length - 1) * 190) / 2,
          y: rowIndex * 175,
        });
      });
  });

  return positions;
}

export function WorldModelGraph({
  graph,
  selectedId,
  onSelect,
}: {
  graph: GraphData;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const [nodes, setNodes, onNodesChange] = useNodesState<NodeData>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState([]);

  useEffect(() => {
    const positions = layout(graph.nodes);
    setNodes(
      graph.nodes.map((node) => ({
        id: node.id,
        position: positions.get(node.id) ?? { x: 0, y: 0 },
        type: 'belief',
        data: { ...node, onSelect, selected: node.id === selectedId },
      }))
    );
    setEdges(
      graph.edges.map((edge, idx) => {
        const target = graph.nodes.find((n) => n.id === edge.target);
        const hot = (target?.p_compromised ?? 0) >= 0.5;
        const color = hot ? '#ef4444' : '#334155';
        return {
          id: `${edge.source}-${edge.target}-${idx}`,
          source: edge.source,
          target: edge.target,
          label: edge.type?.replace(/_/g, ' '),
          labelStyle: { fill: '#64748b', fontSize: 9 },
          labelBgStyle: { fill: '#111827' },
          animated: hot,
          style: { stroke: color, strokeWidth: hot ? 2 : 1.5 },
          markerEnd: { type: MarkerType.ArrowClosed, color },
        };
      })
    );
  }, [graph, selectedId, onSelect, setNodes, setEdges]);

  const nodeTypes = useMemo(() => ({ belief: BeliefNode }), []);

  const onNodeClick: NodeMouseHandler = useCallback(
    (_event, node) => onSelect(node.id),
    [onSelect]
  );

  return (
    <div style={{ height: 620 }} className="relative">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={onNodeClick}
        nodeTypes={nodeTypes as any}
        fitView
        minZoom={0.2}
        attributionPosition="bottom-left"
        className="bg-surface"
      >
        <Controls className="bg-surface-card border-surface-border" />
        <MiniMap
          nodeColor={(node) => compromiseColor((node.data as NodeData)?.p_compromised ?? 0)}
          maskColor="rgba(10, 14, 23, 0.8)"
          className="bg-surface-card border border-surface-border rounded-lg"
        />
        <Background color="#1e293b" gap={20} />
      </ReactFlow>
    </div>
  );
}

/** Legend explaining the visual encoding — important for an unfamiliar viewer. */
export function GraphLegend() {
  return (
    <div className="flex items-center gap-5 flex-wrap text-[10px] text-gray-500">
      <div className="flex items-center gap-1.5">
        <span className="text-gray-400 font-medium">P(compromised):</span>
        {[
          ['< 20%', '#22c55e'],
          ['20-50%', '#eab308'],
          ['50-80%', '#f97316'],
          ['> 80%', '#ef4444'],
        ].map(([label, color]) => (
          <span key={label} className="flex items-center gap-1">
            <span
              className="w-2 h-2 rounded-full"
              style={{ backgroundColor: color as string }}
            />
            {label}
          </span>
        ))}
      </div>
      <span className="flex items-center gap-1.5">
        <span className="text-gray-400 font-medium">Size:</span> scales with probability
      </span>
      <span className="flex items-center gap-1.5">
        <span className="text-gray-400 font-medium">Border:</span>
        <span className="inline-block w-3 h-3 rounded-full border-2 border-dashed border-gray-500" />
        dashed = low confidence
        <span className="inline-block w-3 h-3 rounded-full border-2 border-solid border-gray-400 ml-1" />
        solid = confident
      </span>
    </div>
  );
}
