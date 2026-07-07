import { cn } from '@/lib/utils';

interface BadgeProps {
  variant?: 'default' | 'success' | 'warning' | 'danger' | 'info';
  size?: 'sm' | 'md';
  className?: string;
  children: React.ReactNode;
}

const variantStyles = {
  default: 'bg-gray-500/20 text-gray-300 border-gray-500/30',
  success: 'bg-accent-green/20 text-accent-green border-accent-green/30',
  warning: 'bg-accent-yellow/20 text-accent-yellow border-accent-yellow/30',
  danger: 'bg-accent-red/20 text-accent-red border-accent-red/30',
  info: 'bg-accent-cyan/20 text-accent-cyan border-accent-cyan/30',
};

export function Badge({ variant = 'default', size = 'sm', className, children }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center font-medium border rounded-full whitespace-nowrap',
        size === 'sm' ? 'px-2 py-0.5 text-xs' : 'px-3 py-1 text-sm',
        variantStyles[variant],
        className
      )}
    >
      {children}
    </span>
  );
}
