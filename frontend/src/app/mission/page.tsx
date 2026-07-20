'use client';

import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { api } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Badge } from '@/components/ui/Badge';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { cn } from '@/lib/utils';
import { Target, Users, AlertTriangle, Activity } from 'lucide-react';

function availabilityColor(availability: number): string {
  if (availability >= 0.9) return '#22c55e';
  if (availability >= 0.6) return '#eab308';
  if (availability >= 0.3) return '#f97316';
  return '#ef4444';
}

function safetyVariant(risk: string): 'danger' | 'warning' | 'success' | 'default' {
  const normalized = (risk || '').toLowerCase();
  if (['critical', 'severe', 'high'].includes(normalized)) return 'danger';
  if (['moderate', 'medium', 'elevated'].includes(normalized)) return 'warning';
  if (['low', 'none', 'negligible'].includes(normalized)) return 'success';
  return 'default';
}

export default function MissionPage() {
  const state = useApi(() => api.getMissionImpact(), [], 5000);
  const data = state.data;
  const functions = data?.functions ?? [];

  const totalPopulation = functions.reduce(
    (sum, fn) => sum + (fn.population_affected || 0),
    0
  );

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5">
              <Target className="h-5 w-5 text-accent-orange" />
              <h1 className="text-xl font-bold text-white">Mission Impact</h1>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              What the attack costs in operational terms — availability of each
              business function, people affected, and safety exposure.
            </p>
          </div>

          {data && (
            <div className="flex items-center gap-3 flex-wrap">
              <div className="px-4 py-2.5 rounded-lg bg-surface-card border border-accent-red/25">
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  Overall mission risk
                </p>
                <p className="text-2xl font-bold font-mono text-accent-red">
                  {Math.round(data.overall_mission_risk * 100)}%
                </p>
              </div>
              <div className="px-4 py-2.5 rounded-lg bg-surface-card border border-surface-border">
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  Population affected
                </p>
                <p className="text-2xl font-bold font-mono text-accent-yellow">
                  {totalPopulation.toLocaleString()}
                </p>
              </div>
            </div>
          )}
        </div>

        <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-surface-border">
            <h3 className="text-sm font-semibold text-white">Mission Functions</h3>
            <p className="text-[10px] text-gray-500 font-mono">GET /mission/impact</p>
          </div>

          {state.initialLoading && <LoadingState label="Assessing mission impact…" />}
          {!state.initialLoading && state.error && (
            <ErrorState error={state.error} onRetry={state.refetch} />
          )}
          {!state.initialLoading && !state.error && functions.length === 0 && (
            <EmptyState
              title="No mission functions defined"
              message="No functions are being tracked, so no impact can be computed. Run a scenario to populate the world model."
              icon={<Activity className="h-6 w-6" />}
            />
          )}

          {functions.length > 0 && (
            <div className="divide-y divide-surface-border">
              {functions
                .slice()
                .sort((a, b) => a.availability - b.availability)
                .map((fn) => {
                  const color = availabilityColor(fn.availability);
                  return (
                    <div key={fn.name} className="p-5 space-y-3">
                      <div className="flex items-start justify-between gap-3 flex-wrap">
                        <div className="min-w-0">
                          <h4 className="text-sm font-semibold text-white">
                            {fn.name}
                          </h4>
                          <div className="flex items-center gap-3 mt-1 flex-wrap">
                            <span className="flex items-center gap-1 text-[10px] text-gray-500">
                              <Users className="h-3 w-3" />
                              {fn.population_affected.toLocaleString()} affected
                            </span>
                            <span className="flex items-center gap-1 text-[10px] text-gray-500">
                              <AlertTriangle className="h-3 w-3" />
                              safety:
                              <Badge variant={safetyVariant(fn.safety_risk)} size="sm">
                                {fn.safety_risk || 'unknown'}
                              </Badge>
                            </span>
                          </div>
                        </div>
                        <div className="text-right shrink-0">
                          <p
                            className="text-2xl font-bold font-mono"
                            style={{ color }}
                          >
                            {Math.round(fn.availability * 100)}%
                          </p>
                          <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                            available
                          </p>
                        </div>
                      </div>

                      <div>
                        <div className="h-2 bg-surface rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all duration-700"
                            style={{
                              width: `${fn.availability * 100}%`,
                              backgroundColor: color,
                            }}
                          />
                        </div>
                        {fn.degradation > 0 && (
                          <p className="text-[10px] text-accent-orange font-mono mt-1">
                            degraded by {Math.round(fn.degradation * 100)}%
                          </p>
                        )}
                      </div>

                      {fn.dependent_entities?.length > 0 && (
                        <div>
                          <p className="text-[9px] text-gray-500 uppercase tracking-wider mb-1.5">
                            Depends on {fn.dependent_entities.length}{' '}
                            {fn.dependent_entities.length === 1 ? 'entity' : 'entities'}
                          </p>
                          <div className="flex flex-wrap gap-1">
                            {fn.dependent_entities.map((entity) => (
                              <span
                                key={entity}
                                className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-border/60 text-gray-300"
                              >
                                {entity}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  );
                })}
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
