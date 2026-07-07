'use client';

import { useState, useRef, Suspense } from 'react';
import { Canvas, useFrame, useThree } from '@react-three/fiber';
import { OrbitControls, Text, Sphere, Line, Html } from '@react-three/drei';
import { cn } from '@/lib/utils';
import { TwinNodeDetail } from './TwinNodeDetail';
import * as THREE from 'three';

interface TwinNode {
  id: string;
  label: string;
  type: string;
  status: 'healthy' | 'degraded' | 'compromised' | 'recovering';
  ip: string;
  risk: number;
  position: [number, number, number];
}

interface TwinEdge {
  source: string;
  target: string;
  status: 'normal' | 'attack' | 'suspicious';
  animated?: boolean;
}

const mockNodes: TwinNode[] = [
  { id: 'dc-1', label: 'DC-01', type: 'Server', status: 'compromised', ip: '10.0.1.10', risk: 92, position: [-3, 1, 0] },
  { id: 'sql-1', label: 'SQL-01', type: 'Database', status: 'degraded', ip: '10.0.1.20', risk: 65, position: [0, 1, 3] },
  { id: 'web-1', label: 'WEB-01', type: 'Server', status: 'healthy', ip: '10.0.1.30', risk: 15, position: [3, 1, 0] },
  { id: 'fw-1', label: 'Firewall', type: 'Network', status: 'healthy', ip: '10.0.0.1', risk: 5, position: [0, 3, -3] },
  { id: 'ws-12', label: 'WS-12', type: 'Workstation', status: 'compromised', ip: '10.0.2.12', risk: 88, position: [-2, -1, 2] },
  { id: 'ws-08', label: 'WS-08', type: 'Workstation', status: 'degraded', ip: '10.0.2.8', risk: 45, position: [2, -1, -2] },
  { id: 'ws-15', label: 'WS-15', type: 'Workstation', status: 'healthy', ip: '10.0.2.15', risk: 10, position: [-2, -1, -2] },
];

const mockEdges: TwinEdge[] = [
  { source: 'fw-1', target: 'dc-1', status: 'attack', animated: true },
  { source: 'fw-1', target: 'sql-1', status: 'normal' },
  { source: 'fw-1', target: 'web-1', status: 'normal' },
  { source: 'dc-1', target: 'ws-12', status: 'attack', animated: true },
  { source: 'dc-1', target: 'ws-08', status: 'suspicious', animated: true },
  { source: 'sql-1', target: 'ws-08', status: 'normal' },
  { source: 'web-1', target: 'ws-15', status: 'normal' },
];

const statusColors: Record<string, string> = {
  healthy: '#22c55e',
  degraded: '#eab308',
  compromised: '#ef4444',
  recovering: '#06b6d4',
};

const edgeColors: Record<string, string> = {
  normal: '#1e293b',
  suspicious: '#f97316',
  attack: '#ef4444',
};

function NetworkNode3D({ node, selected, onClick }: { node: TwinNode; selected: boolean; onClick: () => void }) {
  const color = statusColors[node.status];
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (meshRef.current && node.status === 'compromised') {
      meshRef.current.scale.setScalar(1 + Math.sin(state.clock.elapsedTime * 3) * 0.05);
    }
  });

  return (
    <group onClick={onClick}>
      <mesh ref={meshRef} position={node.position}>
        <sphereGeometry args={[selected ? 0.6 : 0.5, 32, 32]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={selected ? 0.6 : 0.2}
          transparent
          opacity={0.9}
        />
      </mesh>
      {selected && (
        <mesh position={node.position}>
          <sphereGeometry args={[0.7, 32, 32]} />
          <meshBasicMaterial color={color} transparent opacity={0.15} />
        </mesh>
      )}
      <Html position={[node.position[0], node.position[1] - 0.9, node.position[2]]} center>
        <div className={cn(
          'px-2 py-1 rounded text-[10px] font-medium whitespace-nowrap',
          'bg-surface-card/90 border shadow-lg backdrop-blur-sm',
          node.status === 'compromised' ? 'border-accent-red/50 text-accent-red' :
          node.status === 'degraded' ? 'border-accent-yellow/30 text-accent-yellow' :
          node.status === 'healthy' ? 'border-accent-green/30 text-accent-green' :
          'border-accent-cyan/30 text-accent-cyan'
        )}>
          {node.label}
        </div>
      </Html>
    </group>
  );
}

function AnimatedEdge({ start, end, color, animated }: { start: [number, number, number]; end: [number, number, number]; color: string; animated?: boolean }) {
  const ref = useRef<any>(null);
  const points = [new THREE.Vector3(...start), new THREE.Vector3(...end)];

  useFrame((state) => {
    if (ref.current && animated) {
      ref.current.material.dashOffset = state.clock.elapsedTime * 2;
    }
  });

  return (
    <line ref={ref}>
      <bufferGeometry>
        <bufferAttribute
          attach="attributes-position"
          count={points.length}
          array={new Float32Array(points.flatMap((p) => [p.x, p.y, p.z]))}
          itemSize={3}
        />
      </bufferGeometry>
      <lineDashedMaterial
        color={color}
        dashSize={animated ? 0.3 : 0}
        gapSize={animated ? 0.2 : 0}
        transparent
        opacity={animated ? 0.8 : 0.3}
        linewidth={1}
      />
    </line>
  );
}

function Scene({ nodes, edges, onNodeClick, selectedId }: {
  nodes: TwinNode[];
  edges: TwinEdge[];
  onNodeClick: (id: string) => void;
  selectedId: string | null;
}) {
  const nodePositions = new Map(nodes.map((n) => [n.id, n.position]));

  return (
    <>
      <ambientLight intensity={0.3} />
      <pointLight position={[5, 5, 5]} intensity={0.8} />
      <pointLight position={[-5, -5, 5]} intensity={0.4} color="#06b6d4" />
      <fog attach="fog" args={['#0a0e17', 10, 20]} />

      <OrbitControls
        enableDamping
        dampingFactor={0.05}
        minDistance={3}
        maxDistance={15}
        autoRotate
        autoRotateSpeed={0.5}
      />

      {edges.map((edge, idx) => {
        const start = nodePositions.get(edge.source);
        const end = nodePositions.get(edge.target);
        if (!start || !end) return null;
        return (
          <AnimatedEdge
            key={`edge-${idx}`}
            start={start}
            end={end}
            color={edgeColors[edge.status]}
            animated={edge.animated}
          />
        );
      })}

      {nodes.map((node) => (
        <NetworkNode3D
          key={node.id}
          node={node}
          selected={selectedId === node.id}
          onClick={() => onNodeClick(node.id)}
        />
      ))}
    </>
  );
}

export function DigitalTwinView() {
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [webglSupported, setWebglSupported] = useState(true);

  const selectedNode = mockNodes.find((n) => n.id === selectedNodeId) || null;

  if (!webglSupported) {
    return (
      <div className="bg-surface-card border border-surface-border rounded-xl p-8 flex items-center justify-center">
        <div className="text-center">
          <p className="text-gray-400 mb-2">WebGL is not available in your browser</p>
          <p className="text-xs text-gray-600">Falling back to 2D network view</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden relative">
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-border">
        <h3 className="text-sm font-semibold text-white">Digital Twin — 3D Network Graph</h3>
        <div className="flex items-center gap-3">
          {Object.entries(statusColors).map(([key, color]) => (
            <div key={key} className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full" style={{ backgroundColor: color }} />
              <span className="text-[10px] text-gray-500 capitalize">{key}</span>
            </div>
          ))}
        </div>
      </div>

      <div style={{ height: 600, width: '100%' }}>
        <Canvas
          camera={{ position: [6, 4, 6], fov: 50 }}
          onCreated={({ gl }) => {
            const isSupported = gl.capabilities.isWebGL2;
            if (!isSupported) setWebglSupported(false);
          }}
        >
          <Suspense fallback={null}>
            <Scene
              nodes={mockNodes}
              edges={mockEdges}
              onNodeClick={(id) => setSelectedNodeId(id === selectedNodeId ? null : id)}
              selectedId={selectedNodeId}
            />
          </Suspense>
        </Canvas>
      </div>

      {selectedNode && (
        <div className="absolute top-16 right-4 w-80 z-10">
          <TwinNodeDetail node={selectedNode} onClose={() => setSelectedNodeId(null)} />
        </div>
      )}
    </div>
  );
}
