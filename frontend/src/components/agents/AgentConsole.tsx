'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Button } from '@/components/ui/Button';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { Search, Filter, Terminal, Pause, Play } from 'lucide-react';

const levelStyles: Record<string, string> = {
  critical: 'text-accent-red bg-accent-red/5 border-l-accent-red',
  high: 'text-accent-orange bg-accent-orange/5 border-l-accent-orange',
  medium: 'text-accent-yellow bg-accent-yellow/5 border-l-accent-yellow',
  low: 'text-gray-300 border-l-accent-cyan',
  info: 'text-gray-500 border-l-gray-600',
};

/**
 * Live event stream.
 *
 * There is no agent-log endpoint in the API, so this console streams the real
 * ingested event feed (GET /threat-intel/indicators) rather than fabricating
 * per-agent log lines, which is what the previous mock version did.
 */
export function AgentConsole() {
  const [search, setSearch] = useState('');
  const [levelFilter, setLevelFilter] = useState('all');
  const [paused, setPaused] = useState(false);

  const state = useApi(
    () => api.getIndicators({ page_size: 100 }),
    [],
    paused ? undefined : 3000
  );

  const events = state.data ?? [];
  const sources = Array.from(new Set(events.map((e) => e.source))).slice(0, 8);

  const filtered = events
    .filter((event) => {
      if (levelFilter !== 'all' && event.severity !== levelFilter) return false;
      if (search) {
        const haystack =
          `${event.title} ${event.description} ${event.source} ${event.event_type}`.toLowerCase();
        if (!haystack.includes(search.toLowerCase())) return false;
      }
      return true;
    })
    .sort(
      (a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime()
    );

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      <div className="px-5 py-3 border-b border-surface-border flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-3">
          <Terminal className="h-5 w-5 text-accent-cyan" />
          <div>
            <h3 className="text-sm font-semibold text-white">Event Console</h3>
            <p className="text-[10px] text-gray-500 font-mono">
              {events.length} events · /threat-intel/indicators
              {sources.length > 0 && ` · sources: ${sources.join(', ')}`}
            </p>
          </div>
        </div>
        <Button
          size="sm"
          variant="ghost"
          onClick={() => setPaused(!paused)}
          icon={
            paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />
          }
        >
          {paused ? 'Resume' : 'Pause'}
        </Button>
      </div>

      <div className="px-5 py-3 border-b border-surface-border flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input
            type="text"
            placeholder="Search events…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-accent-cyan/50"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <Filter className="h-3 w-3 text-gray-500" />
          {['all', 'critical', 'high', 'medium', 'low', 'info'].map((level) => (
            <button
              key={level}
              onClick={() => setLevelFilter(level)}
              className={cn(
                'px-2 py-1 text-[10px] rounded font-medium transition-colors capitalize',
                levelFilter === level
                  ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30'
                  : 'text-gray-500 hover:text-white hover:bg-surface-border'
              )}
            >
              {level}
            </button>
          ))}
        </div>
      </div>

      <div className="max-h-[500px] overflow-y-auto font-mono text-xs">
        {state.initialLoading && <LoadingState label="Connecting to event stream…" />}
        {!state.initialLoading && state.error && (
          <ErrorState error={state.error} onRetry={state.refetch} />
        )}
        {!state.initialLoading && !state.error && events.length === 0 && (
          <EmptyState
            title="Console is quiet"
            message="No events ingested — run a scenario to see live telemetry stream through here."
          />
        )}
        {events.length > 0 && filtered.length === 0 && (
          <div className="px-5 py-8 text-center text-sm text-gray-500">
            No events match your search
          </div>
        )}

        {filtered.map((event) => (
          <div
            key={event.id}
            className={cn(
              'px-5 py-2 border-l-2 border-b border-surface-border/50 hover:bg-surface/50 transition-colors',
              levelStyles[event.severity] ?? levelStyles.info
            )}
          >
            <div className="flex items-start gap-3 flex-wrap">
              <span className="text-gray-600 shrink-0">
                {new Date(event.timestamp).toLocaleTimeString()}
              </span>
              <span className="shrink-0 px-1.5 rounded text-center bg-accent-cyan/10 text-accent-cyan">
                [{event.source}]
              </span>
              <span
                className={cn(
                  'shrink-0 w-14 uppercase',
                  event.severity === 'critical' && 'text-accent-red',
                  event.severity === 'high' && 'text-accent-orange',
                  event.severity === 'medium' && 'text-accent-yellow',
                  (event.severity === 'low' || event.severity === 'info') &&
                    'text-gray-500'
                )}
              >
                {event.severity}
              </span>
              <span className="text-gray-300 flex-1 min-w-0">{event.title}</span>
            </div>
            {event.description && (
              <p className="text-gray-600 mt-0.5 sm:ml-[132px]">{event.description}</p>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
