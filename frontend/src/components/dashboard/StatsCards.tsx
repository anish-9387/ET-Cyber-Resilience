'use client';

import { cn } from '@/lib/utils';
import { ShieldAlert, Activity, Clock, Zap } from 'lucide-react';

interface StatCardProps {
  title: string;
  value: string | number;
  trend: number;
  icon: React.ReactNode;
  color: 'red' | 'yellow' | 'cyan' | 'green';
  subtitle?: string;
}

const colorConfig = {
  red: { bg: 'bg-accent-red/10', border: 'border-accent-red/20', text: 'text-accent-red', glow: 'shadow-glow-red' },
  yellow: { bg: 'bg-accent-yellow/10', border: 'border-accent-yellow/20', text: 'text-accent-yellow', glow: '' },
  cyan: { bg: 'bg-accent-cyan/10', border: 'border-accent-cyan/20', text: 'text-accent-cyan', glow: 'shadow-glow-cyan' },
  green: { bg: 'bg-accent-green/10', border: 'border-accent-green/20', text: 'text-accent-green', glow: 'shadow-glow' },
};

function StatCard({ title, value, trend, icon, color, subtitle }: StatCardProps) {
  const cfg = colorConfig[color];
  const isUp = trend >= 0;

  return (
    <div className={cn('relative overflow-hidden rounded-xl border p-5 transition-all duration-200 hover:scale-[1.02]', cfg.bg, cfg.border, cfg.glow)}>
      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <p className="text-xs text-gray-400 font-medium uppercase tracking-wider">{title}</p>
          <p className="text-2xl font-bold text-white font-mono">{value}</p>
          {subtitle && <p className="text-[10px] text-gray-500">{subtitle}</p>}
        </div>
        <div className={cn('p-2.5 rounded-lg', cfg.bg, cfg.text)}>
          {icon}
        </div>
      </div>
      <div className="mt-3 flex items-center gap-1.5">
        <span className={cn('text-xs font-medium', isUp ? 'text-accent-green' : 'text-accent-red')}>
          {isUp ? '↑' : '↓'} {Math.abs(trend)}%
        </span>
        <span className="text-xs text-gray-500">vs last week</span>
      </div>
    </div>
  );
}

export function StatsCards() {
  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
      <StatCard
        title="Active Threats"
        value={12}
        trend={23}
        icon={<ShieldAlert className="h-5 w-5" />}
        color="red"
        subtitle="3 critical"
      />
      <StatCard
        title="Total Incidents"
        value={47}
        trend={-8}
        icon={<Activity className="h-5 w-5" />}
        color="yellow"
        subtitle="12 new today"
      />
      <StatCard
        title="Mean Time to Detect"
        value="2.4m"
        trend={-15}
        icon={<Clock className="h-5 w-5" />}
        color="cyan"
        subtitle="Improved"
      />
      <StatCard
        title="Mean Time to Respond"
        value="8.7m"
        trend={-22}
        icon={<Zap className="h-5 w-5" />}
        color="green"
        subtitle="Automated"
      />
    </div>
  );
}
