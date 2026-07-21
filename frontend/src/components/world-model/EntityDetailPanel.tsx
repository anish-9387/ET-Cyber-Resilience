'use client';

import { useMemo } from 'react';
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  ReferenceLine,
} from 'recharts';
import { cn } from '@/lib/utils';
import { api, Evidence, Severity } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Badge } from '@/components/ui/Badge';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { ErrorState, LoadingState, EmptyState } from '@/components/ui/States';
import { compromiseColor } from './WorldModelGraph';
import { X, FileSearch, TrendingUp, Link2 } from 'lucide-react';

/* --- Bayesian replay -------------------------------------------------------
 * Mirrors backend/app/world_model/entity_state.py: posterior log-odds are the
 * prior plus each piece of evidence's log-likelihood, weighted by exponential
 * time decay. Replaying it at each evidence timestamp reconstructs how belief
 * actually evolved. These are computed from real returned evidence, not
 * invented — but they are a client-side reconstruction, and the chart says so.
 */
const EVIDENCE_HALF_LIFE_HOURS = 6.0;
const DEFAULT_PRIOR = 0.02;

const logit = (p: number) => {
  const clamped = Math.min(Math.max(p, 1e-9), 1 - 1e-9);
  return Math.log(clamped / (1 - clamped));
};
const sigmoid = (x: number) => 1 / (1 + Math.exp(-x));
const decayWeight = (ageHours: number) =>
  ageHours <= 0 ? 1 : Math.pow(0.5, ageHours / EVIDENCE_HALF_LIFE_HOURS);

function beliefHistory(evidence: Evidence[], prior = DEFAULT_PRIOR) {
  const ordered = evidence
    .slice()
    .sort(
      (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

  const points = ordered.map((item, index) => {
    const now = new Date(item.timestamp).getTime();
    let logOdds = logit(prior);
    for (let j = 0; j <= index; j++) {
      const ageHours = Math.max(
        (now - new Date(ordered[j].timestamp).getTime()) / 3_600_000,
        0
      );
      logOdds += decayWeight(ageHours) * ordered[j].log_likelihood;
    }
    return {
      index: index + 1,
      time: new Date(item.timestamp).toLocaleTimeString(),
      p: Number(sigmoid(Math.min(Math.max(logOdds, -14), 14)).toFixed(4)),
      source: item.source,
      technique: item.technique_id ?? '—',
      description: item.description,
    };
  });

  return [
    {
      index: 0,
      time: 'prior',
      p: prior,
      source: 'prior',
      technique: '—',
      description: 'Base rate before any evidence',
    },
    ...points,
  ];
}

function BeliefTooltip({ active, payload }: any) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="bg-surface-card border border-surface-border rounded-lg px-3 py-2 shadow-xl max-w-xs">
      <p className="text-[10px] text-gray-500 font-mono">{d.time}</p>
      <p className="text-sm font-bold font-mono" style={{ color: compromiseColor(d.p) }}>
        P = {(d.p * 100).toFixed(1)}%
      </p>
      <p className="text-[10px] text-gray-400 mt-1">{d.description}</p>
      <p className="text-[10px] text-gray-600 font-mono mt-0.5">
        {d.source} · {d.technique}
      </p>
    </div>
  );
}

export function EntityDetailPanel({
  entityId,
  onClose,
}: {
  entityId: string;
  onClose: () => void;
}) {
  const state = useApi(() => api.getEntity(entityId), [entityId], 3000);
  const entity = state.data;

  const history = useMemo(
    () => (entity?.evidence?.length ? beliefHistory(entity.evidence) : []),
    [entity]
  );

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden flex flex-col max-h-[calc(100vh-8rem)]">
      <div className="px-5 py-3.5 border-b border-surface-border flex items-center gap-2.5 shrink-0">
        <FileSearch className="h-4 w-4 text-accent-blue shrink-0" />
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-white truncate">
            {entity?.name ?? entityId}
          </h3>
          <p className="text-[10px] text-gray-500 font-mono truncate">{entityId}</p>
        </div>
        <button
          onClick={onClose}
          className="ml-auto p-1 text-gray-400 hover:text-white hover:bg-surface-border rounded transition-colors shrink-0"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="overflow-y-auto">
        {state.initialLoading && <LoadingState label="Loading entity…" />}
        {!state.initialLoading && state.error && (
          <ErrorState error={state.error} onRetry={state.refetch} />
        )}

        {entity && !state.error && (
          <div className="p-5 space-y-5">
            {/* Belief summary */}
            <div className="grid grid-cols-2 gap-3">
              <div className="px-3 py-2.5 rounded-lg bg-surface/60">
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  P(compromised)
                </p>
                <p
                  className="text-xl font-bold font-mono mt-0.5"
                  style={{ color: compromiseColor(entity.p_compromised) }}
                >
                  {(entity.p_compromised * 100).toFixed(1)}%
                </p>
              </div>
              <div className="px-3 py-2.5 rounded-lg bg-surface/60">
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  Confidence
                </p>
                <p className="text-xl font-bold font-mono text-accent-blue mt-0.5">
                  {(entity.confidence * 100).toFixed(0)}%
                </p>
              </div>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              <Badge
                variant={
                  entity.state === 'compromised' || entity.state === 'likely_compromised'
                    ? 'danger'
                    : entity.state === 'suspicious'
                      ? 'warning'
                      : 'success'
                }
                size="sm"
              >
                {entity.state.replace(/_/g, ' ')}
              </Badge>
              <Badge variant="default" size="sm">
                {entity.entity_type}
              </Badge>
              <Badge
                variant={entity.criticality === 'critical' ? 'danger' : 'default'}
                size="sm"
              >
                {entity.criticality}
              </Badge>
              {entity.is_deception && (
                <Badge variant="info" size="sm">
                  decoy
                </Badge>
              )}
              {entity.isolated && (
                <Badge variant="warning" size="sm">
                  isolated
                </Badge>
              )}
            </div>

            {entity.mission_functions?.length > 0 && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">
                  Mission functions
                </p>
                <div className="flex flex-wrap gap-1">
                  {entity.mission_functions.map((fn) => (
                    <Badge key={fn} variant="info" size="sm">
                      {fn}
                    </Badge>
                  ))}
                </div>
              </div>
            )}

            {/* Belief history */}
            <div>
              <div className="flex items-center gap-2 mb-1">
                <TrendingUp className="h-3.5 w-3.5 text-accent-blue" />
                <p className="text-xs font-medium text-white">Bayesian belief history</p>
              </div>
              <p className="text-[10px] text-gray-500 mb-3">
                Posterior replayed from this entity&apos;s evidence using the model&apos;s
                own update rule (prior {DEFAULT_PRIOR}, {EVIDENCE_HALF_LIFE_HOURS}h
                evidence half-life). Reconstructed client-side.
              </p>
              {history.length > 1 ? (
                <div style={{ height: 180 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <LineChart data={history} margin={{ top: 5, right: 8, left: -20, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                      <XAxis
                        dataKey="index"
                        stroke="#475569"
                        tick={{ fontSize: 9 }}
                        tickLine={false}
                      />
                      <YAxis
                        domain={[0, 1]}
                        stroke="#475569"
                        tick={{ fontSize: 9 }}
                        tickLine={false}
                        tickFormatter={(v) => `${Math.round(v * 100)}%`}
                      />
                      <Tooltip content={<BeliefTooltip />} />
                      <ReferenceLine y={0.5} stroke="#f97316" strokeDasharray="4 4" />
                      <ReferenceLine y={0.8} stroke="#ef4444" strokeDasharray="4 4" />
                      <Line
                        type="monotone"
                        dataKey="p"
                        stroke="#06b6d4"
                        strokeWidth={2}
                        dot={{ r: 3, fill: '#06b6d4' }}
                        activeDot={{ r: 5 }}
                        isAnimationActive={false}
                      />
                    </LineChart>
                  </ResponsiveContainer>
                </div>
              ) : (
                <p className="text-xs text-gray-500">
                  No evidence yet — belief is still at the prior.
                </p>
              )}
            </div>

            {/* Evidence list */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <p className="text-xs font-medium text-white">Evidence</p>
                <Badge variant="default" size="sm">
                  {entity.evidence?.length ?? 0} items ·{' '}
                  {entity.independent_evidence_count} independent
                </Badge>
              </div>

              {entity.evidence?.length ? (
                <div className="space-y-2">
                  {entity.evidence
                    .slice()
                    .sort(
                      (a, b) =>
                        new Date(b.timestamp).getTime() -
                        new Date(a.timestamp).getTime()
                    )
                    .map((item) => {
                      const supports = item.log_likelihood >= 0;
                      return (
                        <div
                          key={item.id}
                          className={cn(
                            'px-3 py-2.5 rounded-lg border',
                            supports
                              ? 'bg-accent-red/5 border-accent-red/20'
                              : 'bg-accent-green/5 border-accent-green/20'
                          )}
                        >
                          <div className="flex items-center gap-2 flex-wrap mb-1">
                            <SeverityBadge severity={item.severity as Severity} />
                            {item.technique_id && (
                              <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-border/60 text-gray-300">
                                {item.technique_id}
                              </span>
                            )}
                            <span className="text-[10px] text-gray-500 font-mono">
                              {item.source}
                            </span>
                            {item.derived && (
                              <span
                                className="flex items-center gap-1 text-[9px] text-accent-blue"
                                title={`Propagated depth ${item.propagation_depth} from ${item.origin_entity}`}
                              >
                                <Link2 className="h-2.5 w-2.5" />
                                derived
                              </span>
                            )}
                          </div>
                          <p className="text-xs text-gray-200">{item.description}</p>
                          <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                            <span
                              className={cn(
                                'text-[10px] font-mono font-medium',
                                supports ? 'text-accent-red' : 'text-accent-green'
                              )}
                            >
                              LR {item.likelihood_ratio}× ({supports ? '+' : ''}
                              {item.log_likelihood.toFixed(2)} log-odds)
                            </span>
                            <span className="text-[10px] text-gray-600 font-mono">
                              weight {(item.decay_weight * 100).toFixed(0)}%
                            </span>
                            <span className="text-[10px] text-gray-600 font-mono">
                              {new Date(item.timestamp).toLocaleString()}
                            </span>
                          </div>
                          {item.derived && item.propagation_path?.length > 0 && (
                            <p className="text-[10px] text-gray-600 font-mono mt-1">
                              path: {item.propagation_path.join(' → ')}
                            </p>
                          )}
                        </div>
                      );
                    })}
                </div>
              ) : (
                <EmptyState
                  title="No evidence"
                  message="Nothing has been observed for this entity."
                  className="py-6"
                />
              )}
            </div>

            {entity.neighbors?.length > 0 && (
              <div>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">
                  Neighbors
                </p>
                <div className="flex flex-wrap gap-1">
                  {entity.neighbors.map((n) => (
                    <span
                      key={n}
                      className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-border/60 text-gray-300"
                    >
                      {n}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
