'use client';

import { useCallback, useState } from 'react';
import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import {
  WorldModelGraph,
  GraphLegend,
} from '@/components/world-model/WorldModelGraph';
import {
  AttackerBeliefPanel,
  DefenderBeliefPanel,
} from '@/components/world-model/BeliefPanels';
import { EntityDetailPanel } from '@/components/world-model/EntityDetailPanel';
import { api } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { Badge } from '@/components/ui/Badge';
import { Globe, AlertTriangle, Activity } from 'lucide-react';

export default function WorldModelPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const graphState = useApi(() => api.getWorldModelGraph(), [], 3000);
  const stateSummary = useApi(() => api.getWorldModelState(), [], 3000);

  const handleSelect = useCallback(
    (id: string) => setSelectedId((current) => (current === id ? null : id)),
    []
  );

  const summary = stateSummary.data;
  const graph = graphState.data;
  const graphEmpty = graph !== null && graph.nodes.length === 0;

  return (
    <DashboardLayout>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5">
              <Globe className="h-5 w-5 text-accent-cyan" />
              <h1 className="text-xl font-bold text-white">Living World Model</h1>
              <span className="flex items-center gap-1 text-[10px] text-accent-green font-mono">
                <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
                3s
              </span>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Probabilistic belief over every entity, updated by Bayesian evidence
              fusion. Click a node to inspect its evidence and belief history.
            </p>
          </div>

          {summary && (
            <div className="flex items-center gap-3 flex-wrap">
              <div className="px-3 py-2 rounded-lg bg-surface-card border border-surface-border">
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  Global risk
                </p>
                <p className="text-lg font-bold font-mono text-accent-red">
                  {(summary.global_risk * 100).toFixed(1)}%
                </p>
              </div>
              <div className="px-3 py-2 rounded-lg bg-surface-card border border-surface-border">
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  Compromised
                </p>
                <p className="text-lg font-bold font-mono text-accent-orange">
                  {summary.compromised_count}
                  <span className="text-xs text-gray-500">/{summary.entity_count}</span>
                </p>
              </div>
              <div className="px-3 py-2 rounded-lg bg-surface-card border border-surface-border">
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  Relations
                </p>
                <p className="text-lg font-bold font-mono text-accent-cyan">
                  {summary.relation_count}
                </p>
              </div>
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          {/* Graph */}
          <div className="xl:col-span-2 space-y-6">
            <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
              <div className="px-5 py-3 border-b border-surface-border space-y-2">
                <div className="flex items-center justify-between gap-3 flex-wrap">
                  <h3 className="text-sm font-semibold text-white">
                    Entity Belief Graph
                  </h3>
                  {summary && (
                    <Badge variant="default" size="sm">
                      snapshot {summary.snapshot_id.slice(0, 8)}
                    </Badge>
                  )}
                </div>
                <GraphLegend />
              </div>

              {graphState.initialLoading && (
                <LoadingState label="Loading world model…" />
              )}
              {!graphState.initialLoading && graphState.error && (
                <ErrorState error={graphState.error} onRetry={graphState.refetch} />
              )}
              {!graphState.initialLoading && !graphState.error && graphEmpty && (
                <EmptyState
                  title="World model is empty"
                  message="No entities are being tracked yet. Run a scenario from the Scenario page to populate the model and watch belief propagate."
                  icon={<Activity className="h-6 w-6" />}
                />
              )}
              {graph && !graphState.error && !graphEmpty && (
                <WorldModelGraph
                  graph={graph}
                  selectedId={selectedId}
                  onSelect={handleSelect}
                />
              )}
            </div>

            {/* Highest-risk entities */}
            {summary && summary.entities?.length > 0 && (
              <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
                <div className="px-5 py-3 border-b border-surface-border flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-accent-orange" />
                  <h3 className="text-sm font-semibold text-white">
                    Highest-Belief Entities
                  </h3>
                </div>
                <div className="divide-y divide-surface-border max-h-72 overflow-y-auto">
                  {summary.entities
                    .slice()
                    .sort((a, b) => b.p_compromised - a.p_compromised)
                    .slice(0, 10)
                    .map((entity) => (
                      <button
                        key={entity.id}
                        onClick={() => handleSelect(entity.id)}
                        className="w-full px-5 py-2.5 flex items-center gap-3 hover:bg-surface/40 transition-colors text-left"
                      >
                        <div className="min-w-0 flex-1">
                          <p className="text-xs text-white font-medium truncate">
                            {entity.name}
                          </p>
                          <p className="text-[10px] text-gray-500 font-mono truncate">
                            {entity.entity_type} · {entity.criticality} ·{' '}
                            {entity.evidence_count} evidence
                          </p>
                        </div>
                        <div className="w-28 shrink-0">
                          <div className="h-1.5 bg-surface rounded-full overflow-hidden">
                            <div
                              className="h-full rounded-full transition-all duration-700"
                              style={{
                                width: `${entity.p_compromised * 100}%`,
                                backgroundColor:
                                  entity.p_compromised >= 0.8
                                    ? '#ef4444'
                                    : entity.p_compromised >= 0.5
                                      ? '#f97316'
                                      : entity.p_compromised >= 0.2
                                        ? '#eab308'
                                        : '#22c55e',
                              }}
                            />
                          </div>
                        </div>
                        <span className="text-xs font-mono font-bold text-white w-12 text-right shrink-0">
                          {(entity.p_compromised * 100).toFixed(0)}%
                        </span>
                      </button>
                    ))}
                </div>
              </div>
            )}
          </div>

          {/* Side panels */}
          <div className="space-y-6">
            {selectedId && (
              <EntityDetailPanel
                entityId={selectedId}
                onClose={() => setSelectedId(null)}
              />
            )}
            <AttackerBeliefPanel />
            <DefenderBeliefPanel />
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
