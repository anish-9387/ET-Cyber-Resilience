'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { api, ApiError, CounterfactualResult, Intervention } from '@/lib/api';
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
import {
  GitBranch,
  ArrowRight,
  Clock,
  Target,
  FlaskConical,
  Plus,
  Trash2,
  TrendingDown,
} from 'lucide-react';

const HORIZONS = [30, 60, 120, 240];

const INTERVENTION_TYPES = [
  'isolate_host',
  'disable_account',
  'block_ip',
  'rotate_credentials',
  'patch',
  'deploy_deception',
];

function probabilityColor(p: number): string {
  if (p >= 0.5) return '#ef4444';
  if (p >= 0.25) return '#f97316';
  if (p >= 0.1) return '#eab308';
  return '#22c55e';
}

/* -------------------------------------------------------------------------- */

function FutureCard({
  future,
  rank,
}: {
  future: import('@/lib/api').Future;
  rank: number;
}) {
  const color = probabilityColor(future.probability);

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      <div className="px-5 py-3 border-b border-surface-border">
        <div className="flex items-center gap-2.5 flex-wrap">
          <span
            className="w-6 h-6 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0"
            style={{ backgroundColor: `${color}22`, color }}
          >
            {rank}
          </span>
          <h3 className="text-sm font-semibold text-white flex-1 min-w-0 truncate">
            {future.name}
          </h3>
          <span className="text-lg font-bold font-mono shrink-0" style={{ color }}>
            {Math.round(future.probability * 100)}%
          </span>
        </div>
        <div className="mt-2 h-1.5 bg-surface rounded-full overflow-hidden">
          <div
            className="h-full rounded-full transition-all duration-700"
            style={{
              width: `${future.probability * 100}%`,
              backgroundColor: color,
            }}
          />
        </div>
        <div className="flex items-center gap-3 mt-2 flex-wrap">
          <span className="flex items-center gap-1 text-[10px] text-gray-400">
            <Target className="h-3 w-3" />
            {future.terminal_objective}
          </span>
          <span className="text-[10px] text-gray-500 font-mono">
            mission impact {Math.round(future.mission_impact * 100)}%
          </span>
          <span className="text-[10px] text-gray-500 font-mono">
            confidence {Math.round(future.confidence * 100)}%
          </span>
        </div>
      </div>

      <div className="p-4">
        <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2.5">
          Projected path
        </p>
        <div className="space-y-0">
          {future.path.map((step, idx) => (
            <div key={`${step.technique_id}-${idx}`} className="flex gap-3">
              <div className="flex flex-col items-center shrink-0">
                <div
                  className="w-2.5 h-2.5 rounded-full border-2 mt-1.5"
                  style={{ backgroundColor: color, borderColor: `${color}55` }}
                />
                {idx < future.path.length - 1 && (
                  <div className="w-px flex-1 bg-surface-border my-1" />
                )}
              </div>
              <div className="pb-4 min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-border/60 text-gray-300">
                    {step.technique_id}
                  </span>
                  <span className="text-xs text-white font-medium">{step.name}</span>
                </div>
                <div className="flex items-center gap-3 mt-1 flex-wrap">
                  <span className="text-[10px] text-gray-500">{step.tactic}</span>
                  <span className="flex items-center gap-1 text-[10px] text-accent-cyan font-mono">
                    <ArrowRight className="h-2.5 w-2.5" />
                    {step.target_entity}
                  </span>
                  <span className="flex items-center gap-1 text-[10px] text-gray-500 font-mono">
                    <Clock className="h-2.5 w-2.5" />
                    +{step.eta_minutes}m
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

function CounterfactualPanel() {
  const [interventions, setInterventions] = useState<Intervention[]>([]);
  const [draftType, setDraftType] = useState(INTERVENTION_TYPES[0]);
  const [draftTarget, setDraftTarget] = useState('');
  const [result, setResult] = useState<CounterfactualResult | null>(null);
  const [error, setError] = useState<ApiError | null>(null);
  const [running, setRunning] = useState(false);

  const add = () => {
    if (!draftTarget.trim()) return;
    setInterventions((prev) => [
      ...prev,
      { type: draftType, target: draftTarget.trim() },
    ]);
    setDraftTarget('');
  };

  const run = async () => {
    setRunning(true);
    setError(null);
    try {
      setResult(await api.runCounterfactual(interventions));
    } catch (err) {
      setResult(null);
      setError(
        err instanceof ApiError
          ? err
          : new ApiError('Counterfactual failed', 0, '/forecast/counterfactual')
      );
    } finally {
      setRunning(false);
    }
  };

  const delta = result?.delta ?? 0;

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      <div className="px-5 py-3.5 border-b border-surface-border flex items-center gap-2.5">
        <div className="p-1.5 rounded-lg bg-accent-cyan/15 text-accent-cyan">
          <FlaskConical className="h-4 w-4" />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-white">Counterfactual Analysis</h3>
          <p className="text-[10px] text-gray-500 font-mono">
            &quot;what if we intervened?&quot;
          </p>
        </div>
      </div>

      <div className="p-5 space-y-4">
        {/* Builder */}
        <div className="space-y-2">
          <p className="text-[10px] text-gray-500 uppercase tracking-wider">
            Planned interventions
          </p>
          <div className="flex items-center gap-2 flex-wrap">
            <select
              value={draftType}
              onChange={(e) => setDraftType(e.target.value)}
              className="px-2 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-gray-300 focus:outline-none focus:border-accent-cyan/50"
            >
              {INTERVENTION_TYPES.map((t) => (
                <option key={t} value={t}>
                  {t.replace(/_/g, ' ')}
                </option>
              ))}
            </select>
            <input
              type="text"
              value={draftTarget}
              onChange={(e) => setDraftTarget(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && add()}
              placeholder="target entity id…"
              className="flex-1 min-w-[140px] px-3 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-accent-cyan/50"
            />
            <Button
              size="sm"
              variant="secondary"
              onClick={add}
              icon={<Plus className="h-3.5 w-3.5" />}
            >
              Add
            </Button>
          </div>

          {interventions.length > 0 ? (
            <div className="space-y-1.5">
              {interventions.map((item, idx) => (
                <div
                  key={idx}
                  className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface/60 border border-surface-border"
                >
                  <Badge variant="info" size="sm">
                    {item.type.replace(/_/g, ' ')}
                  </Badge>
                  <span className="text-xs text-white font-mono truncate">
                    {item.target}
                  </span>
                  <button
                    onClick={() =>
                      setInterventions((prev) => prev.filter((_, i) => i !== idx))
                    }
                    className="ml-auto p-1 text-gray-500 hover:text-accent-red transition-colors shrink-0"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
            </div>
          ) : (
            <p className="text-[11px] text-gray-600">
              Add one or more interventions, then run the counterfactual to see how
              much they reduce attack success.
            </p>
          )}
        </div>

        <Button
          variant="primary"
          size="sm"
          onClick={run}
          loading={running}
          disabled={interventions.length === 0}
          className="w-full"
        >
          Run counterfactual
        </Button>

        {error && <InlineError error={error} />}

        {/* Result */}
        {result && (
          <div className="space-y-4 pt-2 border-t border-surface-border">
            <div className="grid grid-cols-3 gap-2">
              <div className="px-3 py-2.5 rounded-lg bg-surface/60 text-center">
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  Baseline
                </p>
                <p className="text-lg font-bold font-mono text-accent-red mt-0.5">
                  {Math.round(result.baseline_attack_success * 100)}%
                </p>
              </div>
              <div className="px-3 py-2.5 rounded-lg bg-surface/60 text-center">
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  With actions
                </p>
                <p className="text-lg font-bold font-mono text-accent-green mt-0.5">
                  {Math.round(result.counterfactual_attack_success * 100)}%
                </p>
              </div>
              <div
                className={cn(
                  'px-3 py-2.5 rounded-lg text-center border',
                  delta < 0
                    ? 'bg-accent-green/10 border-accent-green/25'
                    : 'bg-accent-red/10 border-accent-red/25'
                )}
              >
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  Delta
                </p>
                <p
                  className={cn(
                    'text-lg font-bold font-mono mt-0.5 flex items-center justify-center gap-1',
                    delta < 0 ? 'text-accent-green' : 'text-accent-red'
                  )}
                >
                  {delta < 0 && <TrendingDown className="h-4 w-4" />}
                  {delta > 0 ? '+' : ''}
                  {Math.round(delta * 100)}pp
                </p>
              </div>
            </div>

            <div className="px-3 py-2 rounded-lg bg-surface/60">
              <p className="text-[10px] text-gray-500">Mission impact change</p>
              <p
                className={cn(
                  'text-xs font-mono font-medium',
                  result.mission_impact_delta <= 0
                    ? 'text-accent-green'
                    : 'text-accent-yellow'
                )}
              >
                {result.mission_impact_delta > 0 ? '+' : ''}
                {Math.round(result.mission_impact_delta * 100)}pp
              </p>
            </div>

            {result.per_future?.length > 0 && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">
                  Per-future effect
                </p>
                <div className="space-y-1.5">
                  {result.per_future.map((pf) => (
                    <div
                      key={pf.future_id}
                      className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface/60"
                    >
                      <span className="text-xs text-gray-300 truncate flex-1">
                        {pf.name}
                      </span>
                      <span className="text-[10px] font-mono text-gray-500 shrink-0">
                        {Math.round(pf.baseline_probability * 100)}% →{' '}
                        {Math.round(pf.counterfactual_probability * 100)}%
                      </span>
                      <span
                        className={cn(
                          'text-[10px] font-mono font-bold w-14 text-right shrink-0',
                          pf.delta <= 0 ? 'text-accent-green' : 'text-accent-red'
                        )}
                      >
                        {pf.delta > 0 ? '+' : ''}
                        {Math.round(pf.delta * 100)}pp
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {result.explanation && (
              <div className="px-3 py-2.5 rounded-lg bg-accent-cyan/5 border border-accent-cyan/20">
                <p className="text-[10px] text-accent-cyan uppercase tracking-wider mb-1">
                  Reasoning
                </p>
                <p className="text-xs text-gray-300">{result.explanation}</p>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export default function ForecastPage() {
  const [horizon, setHorizon] = useState(60);
  const state = useApi(() => api.getFutures(horizon), [horizon], 10000);

  const futures = state.data?.futures ?? [];
  const sorted = futures.slice().sort((a, b) => b.probability - a.probability);

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5">
              <GitBranch className="h-5 w-5 text-accent-orange" />
              <h1 className="text-xl font-bold text-white">Multi-Future Forecast</h1>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Branching attack futures with probabilities, and a counterfactual
              sandbox for testing interventions before committing to them.
            </p>
          </div>

          <div className="flex items-center gap-1.5">
            <span className="text-[10px] text-gray-500 mr-1">Horizon:</span>
            {HORIZONS.map((h) => (
              <button
                key={h}
                onClick={() => setHorizon(h)}
                className={cn(
                  'px-2.5 py-1 text-[10px] rounded font-medium transition-colors font-mono',
                  horizon === h
                    ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30'
                    : 'text-gray-500 hover:text-white hover:bg-surface-border'
                )}
              >
                {h}m
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="xl:col-span-2 space-y-4">
            {state.initialLoading && <LoadingState label="Generating futures…" />}
            {!state.initialLoading && state.error && (
              <div className="bg-surface-card border border-surface-border rounded-xl">
                <ErrorState error={state.error} onRetry={state.refetch} />
              </div>
            )}
            {!state.initialLoading && !state.error && sorted.length === 0 && (
              <div className="bg-surface-card border border-surface-border rounded-xl">
                <EmptyState
                  title="No futures projected"
                  message="The forecaster has no active attack to extrapolate from. Run a scenario to generate branching futures."
                />
              </div>
            )}
            {sorted.map((future, idx) => (
              <FutureCard key={future.id} future={future} rank={idx + 1} />
            ))}
            {state.data?.generated_at && (
              <p className="text-[10px] text-gray-600 font-mono">
                Generated {new Date(state.data.generated_at).toLocaleString()}
              </p>
            )}
          </div>

          <div>
            <CounterfactualPanel />
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
