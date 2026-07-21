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
  healthy: { color: 'bg-accent-green' },
  degraded: { color: 'bg-accent-yellow' },
  compromised: { color: 'bg-accent-red' },
  recovering: { color: 'bg-accent-blue' },
  active: { color: 'bg-accent-green' },
  idle: { color: 'bg-gray-500' },
  error: { color: 'bg-accent-red' },
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
          'rounded-full',
          config.color,
          sizes[size]
        )}
      />
      {showLabel && <span className="text-xs text-gray-400">{label || status}</span>}
    </span>
  );
}
