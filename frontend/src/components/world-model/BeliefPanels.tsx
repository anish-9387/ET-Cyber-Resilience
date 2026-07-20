'use client';

import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Badge } from '@/components/ui/Badge';
import { ErrorState, LoadingState, EmptyState } from '@/components/ui/States';
import {
  Crosshair,
  Eye,
  EyeOff,
  Brain,
  Clock,
  Fingerprint,
  Radar,
} from 'lucide-react';

function Meter({ value, color = '#06b6d4' }: { value: number; color?: string }) {
  return (
    <div className="h-1.5 bg-surface rounded-full overflow-hidden">
      <div
        className="h-full rounded-full transition-all duration-700"
        style={{
          width: `${Math.round(Math.min(Math.max(value, 0), 1) * 100)}%`,
          backgroundColor: color,
        }}
      />
    </div>
  );
}

/** GET /world-model/attacker-belief — what Sentinel infers about the adversary. */
export function AttackerBeliefPanel() {
  const state = useApi(() => api.getAttackerBelief(), [], 3000);
  const belief = state.data;

  return (
    <div className="bg-surface-card border border-accent-red/25 rounded-xl overflow-hidden">
      <div className="px-5 py-3.5 border-b border-surface-border flex items-center gap-2.5">
        <div className="p-1.5 rounded-lg bg-accent-red/15 text-accent-red">
          <Crosshair className="h-4 w-4" />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-white">Attacker Belief Model</h3>
          <p className="text-[10px] text-gray-500 font-mono">
            inferred adversary intent
          </p>
        </div>
      </div>

      {state.initialLoading && <LoadingState label="Inferring…" />}
      {!state.initialLoading && state.error && (
        <ErrorState error={state.error} onRetry={state.refetch} />
      )}

      {belief && !state.error && (
        <div className="p-5 space-y-5">
          {/* Objective */}
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">
              Current Objective
            </p>
            <div className="px-3 py-2.5 rounded-lg bg-accent-red/10 border border-accent-red/25">
              <p className="text-sm text-white font-medium">
                {belief.current_objective || 'Unknown'}
              </p>
              <div className="flex items-center justify-between mt-2 mb-1">
                <span className="text-[10px] text-gray-400">Confidence</span>
                <span className="text-[10px] text-accent-red font-mono font-bold">
                  {Math.round(belief.objective_confidence * 100)}%
                </span>
              </div>
              <Meter value={belief.objective_confidence} color="#ef4444" />
            </div>
          </div>

          {/* Attribution */}
          {belief.campaign_match?.actor && (
            <div className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-surface/60">
              <Fingerprint className="h-4 w-4 text-accent-orange shrink-0" />
              <div className="min-w-0">
                <p className="text-[10px] text-gray-500">Campaign attribution</p>
                <p className="text-xs text-white font-medium truncate">
                  {belief.campaign_match.actor}
                </p>
              </div>
              <Badge variant="warning" size="sm" className="ml-auto shrink-0">
                {Math.round(belief.campaign_match.confidence * 100)}%
              </Badge>
            </div>
          )}

          {/* Profile */}
          <div className="grid grid-cols-3 gap-2">
            {[
              ['Sophistication', belief.sophistication],
              ['Risk appetite', belief.risk_appetite],
              ['Persistence', belief.persistence],
            ].map(([label, value]) => (
              <div key={label} className="px-2.5 py-2 rounded-lg bg-surface/60">
                <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                  {label}
                </p>
                <p className="text-xs text-white font-medium capitalize mt-0.5 truncate">
                  {value || '—'}
                </p>
              </div>
            ))}
          </div>

          {/* Current tactic + observed techniques */}
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">
              Current Tactic
            </p>
            <p className="text-xs text-accent-orange font-medium mb-2">
              {belief.current_tactic || 'Unknown'}
            </p>
            {belief.observed_techniques?.length > 0 && (
              <div className="flex flex-wrap gap-1">
                {belief.observed_techniques.map((t) => (
                  <span
                    key={t}
                    className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-border/60 text-gray-300"
                  >
                    {t}
                  </span>
                ))}
              </div>
            )}
          </div>

          {/* Likely next moves */}
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">
              Likely Next Moves
            </p>
            {belief.likely_next?.length ? (
              <div className="space-y-2">
                {belief.likely_next.map((move) => (
                  <div
                    key={move.technique_id}
                    className="px-3 py-2.5 rounded-lg bg-surface/60 border border-surface-border"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-accent-orange/15 text-accent-orange shrink-0">
                        {move.technique_id}
                      </span>
                      <span className="text-xs text-white font-medium truncate">
                        {move.name}
                      </span>
                      <span className="ml-auto text-xs font-mono font-bold text-accent-orange shrink-0">
                        {Math.round(move.probability * 100)}%
                      </span>
                    </div>
                    <Meter value={move.probability} color="#f97316" />
                    <div className="flex items-center gap-3 mt-1.5">
                      <span className="flex items-center gap-1 text-[10px] text-accent-cyan font-mono">
                        <Clock className="h-3 w-3" />
                        ETA ~{move.eta_minutes}m
                      </span>
                      <span className="text-[10px] text-gray-500">{move.tactic}</span>
                    </div>
                    {move.rationale && (
                      <p className="text-[10px] text-gray-400 mt-1.5">
                        {move.rationale}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-500">
                No projected moves — insufficient observed activity.
              </p>
            )}
          </div>

          {/* Inferred knowledge & capabilities */}
          {(belief.inferred_knowledge?.length > 0 ||
            belief.capabilities?.length > 0) && (
            <div className="grid grid-cols-1 gap-3">
              {belief.inferred_knowledge?.length > 0 && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">
                    What the attacker likely knows
                  </p>
                  <ul className="space-y-1">
                    {belief.inferred_knowledge.map((item, idx) => (
                      <li key={idx} className="flex items-start gap-2">
                        <Brain className="h-3 w-3 text-accent-red mt-0.5 shrink-0" />
                        <span className="text-[11px] text-gray-300">{item}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {belief.capabilities?.length > 0 && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">
                    Demonstrated capabilities
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {belief.capabilities.map((c) => (
                      <Badge key={c} variant="danger" size="sm">
                        {c}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** GET /world-model/defender-belief — what Sentinel knows it does NOT know. */
export function DefenderBeliefPanel() {
  const state = useApi(() => api.getDefenderBelief(), [], 3000);
  const belief = state.data;

  return (
    <div className="bg-surface-card border border-accent-cyan/25 rounded-xl overflow-hidden">
      <div className="px-5 py-3.5 border-b border-surface-border flex items-center gap-2.5">
        <div className="p-1.5 rounded-lg bg-accent-cyan/15 text-accent-cyan">
          <Eye className="h-4 w-4" />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-white">Defender Belief Model</h3>
          <p className="text-[10px] text-gray-500 font-mono">
            own uncertainty &amp; collection gaps
          </p>
        </div>
      </div>

      {state.initialLoading && <LoadingState label="Assessing…" />}
      {!state.initialLoading && state.error && (
        <ErrorState error={state.error} onRetry={state.refetch} />
      )}

      {belief && !state.error && (
        <div className="p-5 space-y-5">
          <div>
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-xs text-gray-400">Overall confidence</span>
              <span className="text-sm font-bold font-mono text-accent-cyan">
                {Math.round(belief.overall_confidence * 100)}%
              </span>
            </div>
            <Meter value={belief.overall_confidence} />
            <p className="text-[10px] text-gray-500 mt-1.5">
              How much Sentinel trusts its own picture of the estate.
            </p>
          </div>

          {belief.uncertain_entities?.length > 0 && (
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">
                Most Uncertain Entities
              </p>
              <div className="space-y-2">
                {belief.uncertain_entities.map((entity) => (
                  <div
                    key={entity.entity_id}
                    className="px-3 py-2.5 rounded-lg bg-surface/60 border border-surface-border"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-xs text-white font-medium truncate">
                        {entity.entity_id}
                      </span>
                      <span className="ml-auto text-[10px] font-mono text-gray-400 shrink-0">
                        p={Math.round(entity.p_compromised * 100)}% · conf{' '}
                        {Math.round(entity.confidence * 100)}%
                      </span>
                    </div>
                    {entity.missing_evidence?.length > 0 && (
                      <div className="mt-2">
                        <p className="text-[9px] text-gray-500 uppercase tracking-wider mb-1">
                          Missing evidence
                        </p>
                        <div className="flex flex-wrap gap-1">
                          {entity.missing_evidence.map((m) => (
                            <span
                              key={m}
                              className="text-[9px] px-1.5 py-0.5 rounded bg-accent-yellow/10 text-accent-yellow border border-accent-yellow/20"
                            >
                              {m}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}
                    {entity.recommended_collection?.length > 0 && (
                      <div className="mt-2">
                        <p className="text-[9px] text-gray-500 uppercase tracking-wider mb-1">
                          Recommended collection
                        </p>
                        <ul className="space-y-0.5">
                          {entity.recommended_collection.map((r, idx) => (
                            <li
                              key={idx}
                              className="flex items-start gap-1.5 text-[10px] text-accent-cyan"
                            >
                              <Radar className="h-3 w-3 mt-0.5 shrink-0" />
                              {r}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {[
              ['Coverage gaps', belief.coverage_gaps, 'text-accent-yellow'],
              ['Blind spots', belief.blind_spots, 'text-accent-red'],
            ].map(([label, items, color]) => (
              <div key={label as string}>
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">
                  {label as string}
                </p>
                {(items as string[])?.length ? (
                  <ul className="space-y-1">
                    {(items as string[]).map((item, idx) => (
                      <li key={idx} className="flex items-start gap-1.5">
                        <EyeOff
                          className={cn('h-3 w-3 mt-0.5 shrink-0', color as string)}
                        />
                        <span className="text-[11px] text-gray-300">{item}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="text-[11px] text-gray-600">None reported</p>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
