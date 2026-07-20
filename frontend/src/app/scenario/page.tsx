'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { api, ApiError } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import {
  EmptyState,
  ErrorState,
  InlineError,
  LoadingState,
} from '@/components/ui/States';
import { cn } from '@/lib/utils';
import { compromiseColor } from '@/components/world-model/WorldModelGraph';
import {
  PlayCircle,
  Play,
  RotateCcw,
  Gauge,
  Activity,
  ArrowRight,
} from 'lucide-react';

const SPEEDS = [1, 2, 5, 10];

export default function ScenarioPage() {
  const [speed, setSpeed] = useState(1);
  const [launching, setLaunching] = useState<string | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);

  const scenarios = useApi(() => api.listScenarios(), []);
  // Poll fast while a scenario runs so progress and the world model visibly move.
  const status = useApi(() => api.getScenarioStatus(), [], 2000);
  const world = useApi(() => api.getWorldModelState(), [], 2000);

  const running = status.data?.running ?? false;

  const launch = async (scenarioId: string) => {
    setLaunching(scenarioId);
    setActionError(null);
    try {
      await api.runScenario(scenarioId, speed);
      status.refetch();
      world.refetch();
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? err
          : new ApiError('Failed to launch scenario', 0, '/scenario/run')
      );
    } finally {
      setLaunching(null);
    }
  };

  const reset = async () => {
    setActionError(null);
    try {
      await api.resetWorldModel();
      status.refetch();
      world.refetch();
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? err
          : new ApiError('Failed to reset', 0, '/world-model/reset')
      );
    }
  };

  const list = scenarios.data ?? [];
  const progress =
    status.data && status.data.total_steps > 0
      ? status.data.current_step / status.data.total_steps
      : 0;

  const topEntities = (world.data?.entities ?? [])
    .slice()
    .sort((a, b) => b.p_compromised - a.p_compromised)
    .slice(0, 8);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5">
              <PlayCircle className="h-5 w-5 text-accent-green" />
              <h1 className="text-xl font-bold text-white">Scenario Launcher</h1>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Inject a simulated APT chain and watch the world model update live.
            </p>
          </div>

          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-1.5">
              <Gauge className="h-3.5 w-3.5 text-gray-500" />
              <span className="text-[10px] text-gray-500">Speed:</span>
              {SPEEDS.map((s) => (
                <button
                  key={s}
                  onClick={() => setSpeed(s)}
                  className={cn(
                    'px-2 py-1 text-[10px] rounded font-mono font-medium transition-colors',
                    speed === s
                      ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30'
                      : 'text-gray-500 hover:text-white hover:bg-surface-border'
                  )}
                >
                  {s}×
                </button>
              ))}
            </div>
            <Button
              size="sm"
              variant="secondary"
              onClick={reset}
              icon={<RotateCcw className="h-3.5 w-3.5" />}
            >
              Reset world model
            </Button>
          </div>
        </div>

        {actionError && <InlineError error={actionError} />}

        {/* Live run status */}
        <div
          className={cn(
            'rounded-xl border-2 overflow-hidden transition-colors',
            running
              ? 'border-accent-green/50 bg-accent-green/[0.03]'
              : 'border-surface-border bg-surface-card'
          )}
        >
          <div className="px-5 py-3.5 border-b border-surface-border flex items-center gap-2.5">
            <Activity
              className={cn(
                'h-4 w-4',
                running ? 'text-accent-green animate-pulse' : 'text-gray-500'
              )}
            />
            <h3 className="text-sm font-semibold text-white">Run Status</h3>
            {running && (
              <Badge variant="success" size="sm" className="ml-auto animate-pulse">
                running
              </Badge>
            )}
          </div>

          {status.initialLoading && <LoadingState label="Checking scenario status…" />}
          {!status.initialLoading && status.error && (
            <ErrorState error={status.error} onRetry={status.refetch} />
          )}

          {status.data && !status.error && (
            <div className="p-5 space-y-4">
              {running ? (
                <>
                  <div>
                    <div className="flex items-center justify-between mb-1.5">
                      <span className="text-xs text-white font-medium">
                        {status.data.scenario_name || status.data.scenario_id}
                      </span>
                      <span className="text-xs font-mono text-accent-green">
                        step {status.data.current_step}/{status.data.total_steps}
                      </span>
                    </div>
                    <div className="h-2 bg-surface rounded-full overflow-hidden">
                      <div
                        className="h-full rounded-full bg-accent-green transition-all duration-500"
                        style={{ width: `${progress * 100}%` }}
                      />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
                    {[
                      ['Events injected', status.data.events_injected],
                      [
                        'Started',
                        status.data.started_at
                          ? new Date(status.data.started_at).toLocaleTimeString()
                          : '—',
                      ],
                      ['Entities tracked', world.data?.entity_count ?? '—'],
                    ].map(([label, value]) => (
                      <div
                        key={label as string}
                        className="px-3 py-2 rounded-lg bg-surface/60"
                      >
                        <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                          {label as string}
                        </p>
                        <p className="text-sm font-mono font-bold text-white">
                          {value as string | number}
                        </p>
                      </div>
                    ))}
                  </div>
                </>
              ) : (
                <p className="text-xs text-gray-500">
                  No scenario running. Launch one below to populate the world model.
                </p>
              )}
            </div>
          )}
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Scenario list */}
          <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
            <div className="px-5 py-3.5 border-b border-surface-border">
              <h3 className="text-sm font-semibold text-white">Available Scenarios</h3>
              <p className="text-[10px] text-gray-500 font-mono">GET /scenario/list</p>
            </div>

            {scenarios.initialLoading && <LoadingState label="Loading scenarios…" />}
            {!scenarios.initialLoading && scenarios.error && (
              <ErrorState error={scenarios.error} onRetry={scenarios.refetch} />
            )}
            {!scenarios.initialLoading && !scenarios.error && list.length === 0 && (
              <EmptyState
                title="No scenarios available"
                message="The backend reported no runnable scenarios."
              />
            )}

            {list.length > 0 && (
              <div className="divide-y divide-surface-border">
                {list.map((scenario) => (
                  <div key={scenario.id} className="p-5">
                    <div className="flex items-start justify-between gap-3 flex-wrap">
                      <div className="min-w-0 flex-1">
                        <h4 className="text-sm font-semibold text-white">
                          {scenario.name}
                        </h4>
                        <p className="text-xs text-gray-400 mt-1">
                          {scenario.description}
                        </p>
                        <div className="flex items-center gap-2 mt-2 flex-wrap">
                          {scenario.actor && (
                            <Badge variant="danger" size="sm">
                              {scenario.actor}
                            </Badge>
                          )}
                          {scenario.steps !== undefined && (
                            <span className="text-[10px] text-gray-500 font-mono">
                              {scenario.steps} steps
                            </span>
                          )}
                          {scenario.duration_minutes !== undefined && (
                            <span className="text-[10px] text-gray-500 font-mono">
                              ~{scenario.duration_minutes}m
                            </span>
                          )}
                        </div>
                      </div>
                      <Button
                        size="sm"
                        variant="primary"
                        loading={launching === scenario.id}
                        disabled={running}
                        onClick={() => launch(scenario.id)}
                        icon={<Play className="h-3.5 w-3.5" />}
                      >
                        Run
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Live world model reaction */}
          <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
            <div className="px-5 py-3.5 border-b border-surface-border flex items-center gap-2">
              <h3 className="text-sm font-semibold text-white">
                World Model Reaction
              </h3>
              {world.data && (
                <span className="ml-auto text-[10px] text-gray-500 font-mono">
                  global risk{' '}
                  <span className="text-accent-red font-bold">
                    {(world.data.global_risk * 100).toFixed(1)}%
                  </span>
                </span>
              )}
            </div>

            {world.initialLoading && <LoadingState label="Reading world model…" />}
            {!world.initialLoading && world.error && (
              <ErrorState error={world.error} onRetry={world.refetch} />
            )}
            {!world.initialLoading && !world.error && topEntities.length === 0 && (
              <EmptyState
                title="World model is empty"
                message="Launch a scenario and entity beliefs will start updating here every 2 seconds."
              />
            )}

            {topEntities.length > 0 && (
              <>
                <div className="divide-y divide-surface-border max-h-[420px] overflow-y-auto">
                  {topEntities.map((entity) => (
                    <div key={entity.id} className="px-5 py-2.5 flex items-center gap-3">
                      <div className="min-w-0 flex-1">
                        <p className="text-xs text-white font-medium truncate">
                          {entity.name}
                        </p>
                        <p className="text-[10px] text-gray-500 font-mono truncate">
                          {entity.state.replace(/_/g, ' ')} · {entity.evidence_count}{' '}
                          evidence
                        </p>
                      </div>
                      <div className="w-24 shrink-0">
                        <div className="h-1.5 bg-surface rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full transition-all duration-500"
                            style={{
                              width: `${entity.p_compromised * 100}%`,
                              backgroundColor: compromiseColor(entity.p_compromised),
                            }}
                          />
                        </div>
                      </div>
                      <span
                        className="text-xs font-mono font-bold w-11 text-right shrink-0"
                        style={{ color: compromiseColor(entity.p_compromised) }}
                      >
                        {(entity.p_compromised * 100).toFixed(0)}%
                      </span>
                    </div>
                  ))}
                </div>
                <a
                  href="/world-model"
                  className="flex items-center justify-center gap-1.5 px-5 py-3 border-t border-surface-border text-xs text-accent-cyan hover:bg-surface/40 transition-colors"
                >
                  Open the full world model
                  <ArrowRight className="h-3.5 w-3.5" />
                </a>
              </>
            )}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
