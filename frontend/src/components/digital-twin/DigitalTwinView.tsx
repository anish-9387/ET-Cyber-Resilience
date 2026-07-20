'use client';

import { useMemo, useRef, useState, Suspense } from 'react';
import { Canvas, useFrame } from '@react-three/fiber';
import { OrbitControls, Html } from '@react-three/drei';
import * as THREE from 'three';
import { cn } from '@/lib/utils';
import { api, Asset, AssetGraph, Criticality } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { TwinNodeDetail } from './TwinNodeDetail';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';

const criticalityColors: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
};

interface PositionedAsset {
  asset: Asset;
  position: [number, number, number];
}

/**
 * Deterministic 3D layout: assets are placed on concentric rings, one ring per
 * criticality tier, so the most critical infrastructure sits at the centre.
 * Positions are derived from the data — the previous version hardcoded them.
 */
function layoutAssets(assets: Asset[]): PositionedAsset[] {
  const tiers: Criticality[] = ['critical', 'high', 'medium', 'low'];
  const grouped = new Map<string, Asset[]>();
  for (const asset of assets) {
    const key = tiers.includes(asset.criticality) ? asset.criticality : 'low';
    const list = grouped.get(key) ?? [];
    list.push(asset);
    grouped.set(key, list);
  }

  const positioned: PositionedAsset[] = [];
  tiers.forEach((tier, tierIndex) => {
    const group = (grouped.get(tier) ?? []).slice().sort((a, b) => a.id.localeCompare(b.id));
    const radius = tierIndex === 0 ? 0.8 : tierIndex * 2.4;
    const y = 2 - tierIndex * 1.3;
    group.forEach((asset, idx) => {
      const angle = group.length === 1 ? 0 : (idx / group.length) * Math.PI * 2;
      positioned.push({
        asset,
        position: [
          Math.cos(angle) * radius,
          y + (idx % 2 === 0 ? 0.25 : -0.25),
          Math.sin(angle) * radius,
        ],
      });
    });
  });

  return positioned;
}

function AssetNode3D({
  item,
  selected,
  onClick,
}: {
  item: PositionedAsset;
  selected: boolean;
  onClick: () => void;
}) {
  const color = criticalityColors[item.asset.criticality] || '#6b7280';
  const meshRef = useRef<THREE.Mesh>(null);

  useFrame((state) => {
    if (meshRef.current && item.asset.criticality === 'critical') {
      meshRef.current.scale.setScalar(
        1 + Math.sin(state.clock.elapsedTime * 2.5) * 0.05
      );
    }
  });

  return (
    <group onClick={onClick}>
      <mesh ref={meshRef} position={item.position}>
        <sphereGeometry args={[selected ? 0.42 : 0.34, 32, 32]} />
        <meshStandardMaterial
          color={color}
          emissive={color}
          emissiveIntensity={selected ? 0.6 : 0.2}
          transparent
          opacity={0.9}
        />
      </mesh>
      {selected && (
        <mesh position={item.position}>
          <sphereGeometry args={[0.55, 32, 32]} />
          <meshBasicMaterial color={color} transparent opacity={0.15} />
        </mesh>
      )}
      <Html
        position={[item.position[0], item.position[1] - 0.7, item.position[2]]}
        center
        distanceFactor={12}
      >
        <div
          className={cn(
            'px-2 py-1 rounded text-[10px] font-medium whitespace-nowrap',
            'bg-surface-card/90 border shadow-lg backdrop-blur-sm'
          )}
          style={{ borderColor: `${color}66`, color }}
        >
          {item.asset.name}
        </div>
      </Html>
    </group>
  );
}

function Edge3D({
  start,
  end,
}: {
  start: [number, number, number];
  end: [number, number, number];
}) {
  const geometry = useMemo(() => {
    const g = new THREE.BufferGeometry();
    g.setAttribute(
      'position',
      new THREE.Float32BufferAttribute([...start, ...end], 3)
    );
    return g;
  }, [start, end]);

  return (
    <primitive
      object={
        new THREE.Line(
          geometry,
          new THREE.LineBasicMaterial({
            color: '#334155',
            transparent: true,
            opacity: 0.5,
          })
        )
      }
    />
  );
}

function Scene({
  items,
  graph,
  selectedId,
  onSelect,
}: {
  items: PositionedAsset[];
  graph: AssetGraph;
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const positions = useMemo(
    () => new Map(items.map((i) => [i.asset.id, i.position])),
    [items]
  );

  return (
    <>
      <ambientLight intensity={0.4} />
      <pointLight position={[5, 5, 5]} intensity={0.8} />
      <pointLight position={[-5, -5, 5]} intensity={0.4} color="#06b6d4" />
      <fog attach="fog" args={['#0a0e17', 12, 26]} />

      <OrbitControls
        enableDamping
        dampingFactor={0.05}
        minDistance={4}
        maxDistance={22}
        autoRotate
        autoRotateSpeed={0.4}
      />

      {graph.relationships.map((rel) => {
        const start = positions.get(rel.source_asset_id);
        const end = positions.get(rel.target_asset_id);
        if (!start || !end) return null;
        return <Edge3D key={rel.id} start={start} end={end} />;
      })}

      {items.map((item) => (
        <AssetNode3D
          key={item.asset.id}
          item={item}
          selected={selectedId === item.asset.id}
          onClick={() => onSelect(item.asset.id)}
        />
      ))}
    </>
  );
}

/** 3D asset topology from GET /digital-twin/graph. */
export function DigitalTwinView() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [webglSupported, setWebglSupported] = useState(true);

  const state = useApi(() => api.getTwinGraph(), [], 15000);
  const graph = state.data;

  const items = useMemo(() => (graph ? layoutAssets(graph.nodes) : []), [graph]);
  const selectedAsset =
    items.find((i) => i.asset.id === selectedId)?.asset ?? null;

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden relative">
      <div className="flex items-center justify-between px-5 py-3 border-b border-surface-border gap-3 flex-wrap">
        <div>
          <h3 className="text-sm font-semibold text-white">
            Digital Twin — 3D Asset Graph
          </h3>
          <p className="text-[10px] text-gray-500 font-mono">
            {graph
              ? `${graph.nodes.length} assets · ${graph.relationships.length} relationships`
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

      {state.initialLoading && <LoadingState label="Loading digital twin…" />}
      {!state.initialLoading && state.error && (
        <ErrorState error={state.error} onRetry={state.refetch} />
      )}
      {!state.initialLoading && !state.error && items.length === 0 && (
        <EmptyState
          title="No assets to render"
          message="The digital twin graph is empty. Note that it only returns assets that participate in at least one relationship."
        />
      )}

      {!webglSupported && items.length > 0 && (
        <div className="p-8 text-center">
          <p className="text-gray-400 mb-2">WebGL is not available in your browser</p>
          <p className="text-xs text-gray-600">
            Use the 2D topology on the Dashboard instead.
          </p>
        </div>
      )}

      {webglSupported && items.length > 0 && graph && (
        <div style={{ height: 600, width: '100%' }}>
          <Canvas
            camera={{ position: [7, 5, 7], fov: 50 }}
            onCreated={({ gl }) => {
              if (!gl.capabilities.isWebGL2) setWebglSupported(false);
            }}
          >
            <Suspense fallback={null}>
              <Scene
                items={items}
                graph={graph}
                selectedId={selectedId}
                onSelect={(id) => setSelectedId(id === selectedId ? null : id)}
              />
            </Suspense>
          </Canvas>
        </div>
      )}

      {selectedAsset && (
        <div className="absolute top-16 right-4 w-80 z-10">
          <TwinNodeDetail
            asset={selectedAsset}
            onClose={() => setSelectedId(null)}
          />
        </div>
      )}
    </div>
  );
}
