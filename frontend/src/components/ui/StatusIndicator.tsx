'use client';

import { cn } from '@/lib/utils';

interface StatusIndicatorProps {
  status: 'healthy' | 'degraded' | 'compromised' | 'recovering' | 'active' | 'idle' | 'error';
  size?: 'sm' | 'md' | 'lg';
  label?: string;
  showLabel?: boolean;
  className?: string;
}

const statusConfig = {
  healthy: { color: 'bg-accent-green', glow: 'shadow-glow' },
  degraded: { color: 'bg-accent-yellow', glow: '' },
  compromised: { color: 'bg-accent-red', glow: 'shadow-glow-red' },
  recovering: { color: 'bg-accent-cyan', glow: 'shadow-glow-cyan' },
  active: { color: 'bg-accent-green', glow: 'shadow-glow' },
  idle: { color: 'bg-gray-500', glow: '' },
  error: { color: 'bg-accent-red', glow: 'shadow-glow-red' },
};

const sizes = {
  sm: 'h-2 w-2',
  md: 'h-3 w-3',
  lg: 'h-4 w-4',
};

export function StatusIndicator({ status, size = 'md', label, showLabel = true, className }: StatusIndicatorProps) {
  const config = statusConfig[status];
  return (
    <span className={cn('inline-flex items-center gap-2', className)}>
      <span
        className={cn(
          'rounded-full animate-pulse',
          config.color,
          config.glow,
          sizes[size]
        )}
      />
      {showLabel && <span className="text-xs text-gray-400">{label || status}</span>}
    </span>
  );
}
