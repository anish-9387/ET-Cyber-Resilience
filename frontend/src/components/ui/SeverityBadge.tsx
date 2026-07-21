import { cn } from '@/lib/utils';

interface SeverityBadgeProps {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  size?: 'sm' | 'md';
  className?: string;
}

const severityConfig = {
  critical: { bg: 'bg-accent-red/20', text: 'text-accent-red', border: 'border-accent-red/30', dot: 'bg-accent-red' },
  high: { bg: 'bg-accent-orange/20', text: 'text-accent-orange', border: 'border-accent-orange/30', dot: 'bg-accent-orange' },
  medium: { bg: 'bg-accent-yellow/20', text: 'text-accent-yellow', border: 'border-accent-yellow/30', dot: 'bg-accent-yellow' },
  low: { bg: 'bg-accent-blue/20', text: 'text-accent-blue', border: 'border-accent-blue/30', dot: 'bg-accent-blue' },
  info: { bg: 'bg-blue-500/20', text: 'text-blue-400', border: 'border-blue-500/30', dot: 'bg-blue-500' },
};

export function SeverityBadge({ severity, size = 'sm', className }: SeverityBadgeProps) {
  const config = severityConfig[severity];
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 font-medium border rounded-full',
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm',
        config.bg,
        config.text,
        config.border,
        className
      )}
    >
      <span className={cn('w-1.5 h-1.5 rounded-full', config.dot)} />
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  );
}
