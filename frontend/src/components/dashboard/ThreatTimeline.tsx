'use client';

import { cn } from '@/lib/utils';
import { api, Severity } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Timeline } from '@/components/ui/Timeline';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';

const severityColors: Record<string, 'red' | 'orange' | 'yellow' | 'cyan' | 'gray'> = {
  critical: 'red',
  high: 'orange',
  medium: 'yellow',
  low: 'cyan',
  info: 'gray',
};

function severityBadge(severity: Severity) {
  const styles: Record<string, string> = {
    critical: 'bg-accent-red/20 text-accent-red border-accent-red/30',
    high: 'bg-accent-orange/20 text-accent-orange border-accent-orange/30',
    medium: 'bg-accent-yellow/20 text-accent-yellow border-accent-yellow/30',
    low: 'bg-accent-blue/20 text-accent-blue border-accent-blue/30',
    info: 'bg-gray-500/20 text-gray-400 border-gray-500/30',
  };
  return (
    <span
      className={cn(
        'text-[10px] px-1.5 py-0.5 rounded border font-medium',
        styles[severity] ?? styles.info
      )}
    >
      {severity.toUpperCase()}
    </span>
  );
}

/** Chronological event feed from /threat-intel/indicators. */
export function ThreatTimeline() {
  const state = useApi(() => api.getIndicators({ page_size: 30 }), [], 5000);

  const events = (state.data ?? [])
    .slice()
    .sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    )
    .map((e) => {
      const technique = e.tags?.find((t) => /^T\d{4}/.test(t));
      return {
        id: e.id,
        timestamp: new Date(e.timestamp).toLocaleTimeString(),
        title: e.title,
        description: e.description,
        color: severityColors[e.severity] ?? 'gray',
        badge: (
          <div className="flex items-center gap-1.5">
            {severityBadge(e.severity)}
            {technique && (
              <span className="text-[10px] text-gray-500 font-mono bg-surface-border/50 px-1.5 py-0.5 rounded">
                {technique}
              </span>
            )}
          </div>
        ),
      };
    });

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">Threat Timeline</h3>
        {!state.error && !state.initialLoading && (
          <div className="flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-green" />
            <span className="text-[10px] text-gray-500 font-mono">Active</span>
          </div>
        )}
      </div>

      <div className="max-h-[400px] overflow-y-auto custom-scrollbar">
        {state.initialLoading && <LoadingState label="Loading timeline…" />}
        {!state.initialLoading && state.error && (
          <ErrorState error={state.error} onRetry={state.refetch} />
        )}
        {!state.initialLoading && !state.error && events.length === 0 && (
          <EmptyState
            title="Timeline is empty"
            message="No events ingested — run a scenario to see the attack unfold here."
          />
        )}
        {events.length > 0 && <Timeline events={events} animate />}
      </div>
    </div>
  );
}
