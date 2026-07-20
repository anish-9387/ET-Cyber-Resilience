'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { api, Severity } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { Bell, Filter } from 'lucide-react';

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function relativeTime(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const seconds = Math.floor((Date.now() - then) / 1000);
  if (seconds < 60) return `${Math.max(seconds, 0)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/**
 * Live security events from /threat-intel/indicators.
 *
 * There is no alert acknowledge/resolve endpoint in the API, so this panel is
 * read-only — the previous version had accept/resolve buttons that only mutated
 * local state and gave the false impression of a persisted workflow.
 */
export function AlertsPanel() {
  const [filter, setFilter] = useState<string>('all');
  const state = useApi(
    () => api.getIndicators({ page_size: 50 }),
    [],
    5000
  );

  const events = state.data ?? [];
  const filtered = events
    .filter((e) => filter === 'all' || e.severity === filter)
    .sort(
      (a, b) =>
        (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9) ||
        new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

  const criticalCount = events.filter((e) => e.severity === 'critical').length;

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b border-surface-border">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Bell className="h-5 w-5 text-gray-400" />
              {criticalCount > 0 && (
                <span className="absolute -top-1 -right-1 w-2 h-2 bg-accent-red rounded-full animate-pulse" />
              )}
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">Security Events</h3>
              <p className="text-[10px] text-gray-500 font-mono">
                {state.initialLoading ? 'loading…' : `${events.length} in feed`}
              </p>
            </div>
          </div>
          {!state.error && (
            <div className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
              <span className="text-[10px] text-gray-500">Live</span>
            </div>
          )}
        </div>

        <div className="flex items-center gap-1.5">
          <Filter className="h-3 w-3 text-gray-500" />
          {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                'px-2 py-1 text-[10px] rounded font-medium transition-colors capitalize',
                filter === f
                  ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30'
                  : 'text-gray-500 hover:text-white hover:bg-surface-border'
              )}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="divide-y divide-surface-border max-h-[480px] overflow-y-auto">
        {state.initialLoading && <LoadingState label="Loading events…" />}

        {!state.initialLoading && state.error && (
          <ErrorState error={state.error} onRetry={state.refetch} />
        )}

        {!state.initialLoading && !state.error && events.length === 0 && (
          <EmptyState
            title="No security events"
            message="Nothing has been ingested yet. Run a scenario or POST telemetry to /ingest/event to populate this feed."
          />
        )}

        {!state.initialLoading &&
          !state.error &&
          events.length > 0 &&
          filtered.length === 0 && (
            <div className="px-5 py-8 text-center text-sm text-gray-500">
              No events match the current filter
            </div>
          )}

        {filtered.map((event) => {
          const technique = event.tags?.find((t) => /^T\d{4}/.test(t));
          return (
            <div
              key={event.id}
              className={cn(
                'px-5 py-3 transition-colors duration-150',
                event.severity === 'critical' && 'bg-accent-red/5'
              )}
            >
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <SeverityBadge severity={event.severity as Severity} />
                  <span className="text-[10px] text-gray-500 font-mono">
                    {event.id.slice(0, 8)}
                  </span>
                  {technique && (
                    <span className="text-[10px] text-gray-600 bg-surface-border/50 px-1.5 py-0.5 rounded font-mono">
                      {technique}
                    </span>
                  )}
                  <span className="text-[10px] text-gray-600">{event.source}</span>
                </div>
                <h4 className="text-sm font-medium text-white">{event.title}</h4>
                <p className="text-xs text-gray-400 mt-0.5">{event.description}</p>
                <p className="text-[10px] text-gray-600 mt-1">
                  {relativeTime(event.timestamp)}
                </p>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
