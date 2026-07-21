'use client';

import { api } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { ErrorState, LoadingState, EmptyState } from '@/components/ui/States';
import { ArrowRight, Target, AlertTriangle, Siren } from 'lucide-react';

/**
 * Attacker intent and next-move prediction, sourced from
 * GET /world-model/attacker-belief.
 */
export function AttackPredictionCard() {
  const state = useApi(() => api.getAttackerBelief(), [], 5000);
  const belief = state.data;
  const next = belief?.likely_next?.[0];

  return (
    <div className="bg-surface-card border border-accent-red/30 rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b border-surface-border flex items-center gap-3">
        <div className="p-2 rounded-lg bg-accent-red/20 text-accent-red">
          <Siren className="h-4 w-4" />
        </div>
        <div>
          <h3 className="text-sm font-semibold text-white">Attack Prediction</h3>
          <p className="text-[10px] text-gray-500 font-mono">
            world-model · attacker belief
          </p>
        </div>
        {belief && (
          <div className="ml-auto flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-red" />
            <span className="text-[10px] text-accent-red font-mono">Active</span>
          </div>
        )}
      </div>

      {state.initialLoading && <LoadingState label="Reading attacker belief…" />}

      {!state.initialLoading && state.error && (
        <ErrorState error={state.error} onRetry={state.refetch} />
      )}

      {!state.initialLoading && !state.error && belief && !next && (
        <EmptyState
          title="No predicted next move"
          message="The world model has not observed enough activity to project the attacker's next step."
        />
      )}

      {!state.initialLoading && !state.error && belief && next && (
        <div className="p-5 space-y-5">
          <div className="flex items-center gap-3">
            <div className="flex-1 min-w-0">
              <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">
                Current Tactic
              </p>
              <div className="px-3 py-2 rounded-lg bg-accent-red/10 border border-accent-red/30">
                <p className="text-xs text-accent-red font-medium truncate">
                  {belief.current_tactic || 'Unknown'}
                </p>
              </div>
            </div>
            <div className="shrink-0 mt-5">
              <div className="p-1.5 rounded-full bg-accent-red/20">
                <ArrowRight className="h-4 w-4 text-accent-red" />
              </div>
            </div>
            <div className="flex-1 min-w-0">
              <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">
                Predicted Next
              </p>
              <div className="px-3 py-2 rounded-lg bg-accent-orange/10 border border-accent-orange/30">
                <p className="text-xs text-accent-orange font-medium truncate">
                  {next.name} ({next.technique_id})
                </p>
              </div>
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-gray-400">Probability of progression</span>
              <span className="text-sm font-bold text-accent-red font-mono">
                {Math.round(next.probability * 100)}%
              </span>
            </div>
            <div className="h-2 bg-surface rounded-full overflow-hidden">
              <div
                className="h-full rounded-full bg-gradient-to-r from-accent-orange to-accent-red transition-all duration-1000"
                style={{ width: `${Math.round(next.probability * 100)}%` }}
              />
            </div>
          </div>

          <div className="flex items-center gap-3 px-3 py-2 rounded-lg bg-surface/50">
            <div className="p-1.5 rounded bg-accent-blue/10 text-accent-blue">
              <AlertTriangle className="h-3.5 w-3.5" />
            </div>
            <div>
              <p className="text-[10px] text-gray-500">Estimated time to next step</p>
              <p className="text-xs text-accent-blue font-mono font-medium">
                ~{next.eta_minutes} minutes
              </p>
            </div>
          </div>

          <div className="flex items-start gap-3 px-3 py-2 rounded-lg bg-surface/50">
            <div className="p-1.5 rounded bg-accent-red/10 text-accent-red shrink-0">
              <Target className="h-3.5 w-3.5" />
            </div>
            <div className="min-w-0">
              <p className="text-[10px] text-gray-500">Objective</p>
              <p className="text-xs text-white font-medium">
                {belief.current_objective}
              </p>
              <p className="text-[10px] text-gray-500 font-mono mt-0.5">
                confidence {Math.round(belief.objective_confidence * 100)}%
                {belief.campaign_match?.actor
                  ? ` · attributed ${belief.campaign_match.actor} (${Math.round(
                      belief.campaign_match.confidence * 100
                    )}%)`
                  : ''}
              </p>
            </div>
          </div>

          {belief.likely_next.length > 1 && (
            <div>
              <p className="text-xs text-gray-400 font-medium mb-2">
                Other likely moves
              </p>
              <div className="space-y-1.5">
                {belief.likely_next.slice(1, 5).map((move) => (
                  <div
                    key={move.technique_id}
                    className="flex items-center gap-2 px-2.5 py-2 rounded-lg bg-surface/50"
                  >
                    <span className="text-[10px] text-gray-500 font-mono shrink-0">
                      {move.technique_id}
                    </span>
                    <span className="text-xs text-gray-300 truncate">{move.name}</span>
                    <span className="ml-auto text-[10px] text-accent-orange font-mono shrink-0">
                      {Math.round(move.probability * 100)}%
                    </span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
