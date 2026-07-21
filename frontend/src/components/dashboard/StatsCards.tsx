'use client';

import { cn } from '@/lib/utils';
import { api } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { InlineError } from '@/components/ui/States';
import { ShieldAlert, Activity, Server, Bot } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  icon: React.ReactNode;
  color: 'red' | 'yellow' | 'cyan' | 'green';
  subtitle?: string;
  loading?: boolean;
}

const colorConfig = {
  red: { bg: 'bg-accent-red/10', border: 'border-accent-red/20', text: 'text-accent-red' },
  yellow: { bg: 'bg-accent-yellow/10', border: 'border-accent-yellow/20', text: 'text-accent-yellow' },
  cyan: { bg: 'bg-accent-blue/10', border: 'border-accent-blue/20', text: 'text-accent-blue' },
  green: { bg: 'bg-accent-green/10', border: 'border-accent-green/20', text: 'text-accent-green' },
};

function StatCard({ title, value, icon, color, subtitle, loading }: StatCardProps) {
  const cfg = colorConfig[color];

  return (
    <div
      className={cn(
        'relative overflow-hidden rounded-xl border p-5',
        cfg.bg,
        cfg.border,
      )}
    >
      <div className="flex items-start justify-between">
        <div className="space-y-1 min-w-0">
          <p className="text-xs text-gray-400 font-medium uppercase tracking-wider">{title}</p>
          {loading ? (
            <div className="h-8 w-16 rounded bg-surface-border/60 animate-pulse" />
          ) : (
            <p className="text-2xl font-bold text-white font-mono">{value}</p>
          )}
          {subtitle && !loading && (
            <p className="text-[10px] text-gray-500">{subtitle}</p>
          )}
        </div>
        <div className={cn('p-2.5 rounded-lg shrink-0', cfg.bg, cfg.text)}>{icon}</div>
      </div>
    </div>
  );
}

/**
 * Live counts from /analytics/dashboard. There is no historical series behind
 * these numbers, so no "vs last week" trend is claimed — the previous version
 * showed invented percentages.
 */
export function StatsCards() {
  const state = useApi(() => api.getDashboard(), [], 5000);
  const d = state.data;

  if (state.error && !d) {
    return <InlineError error={state.error} />;
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        title="Open Incidents"
        value={d?.incidents.open ?? '—'}
        icon={<ShieldAlert className="h-5 w-5" />}
        color="red"
        subtitle={d ? `${d.incidents.critical} critical` : undefined}
        loading={state.initialLoading}
      />
      <StatCard
        title="Incidents (24h)"
        value={d?.incidents.last_24h ?? '—'}
        icon={<Activity className="h-5 w-5" />}
        color="yellow"
        subtitle={d ? `${d.incidents.total} total` : undefined}
        loading={state.initialLoading}
      />
      <StatCard
        title="Assets Monitored"
        value={d?.assets.total ?? '—'}
        icon={<Server className="h-5 w-5" />}
        color="cyan"
        subtitle={d ? `${d.assets.critical} critical` : undefined}
        loading={state.initialLoading}
      />
      <StatCard
        title="Active Agents"
        value={d?.agents.active ?? '—'}
        icon={<Bot className="h-5 w-5" />}
        color="green"
        subtitle={d ? `${d.agents.total} registered` : undefined}
        loading={state.initialLoading}
      />
    </div>
  );
}
