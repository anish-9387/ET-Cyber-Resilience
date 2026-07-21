import { cn } from '@/lib/utils';

interface TimelineEvent {
  id: string | number;
  timestamp: string;
  title: string;
  description?: string;
  color?: 'red' | 'orange' | 'yellow' | 'cyan' | 'green' | 'gray';
  icon?: React.ReactNode;
  badge?: React.ReactNode;
}

interface TimelineProps {
  events: TimelineEvent[];
  className?: string;
  animate?: boolean;
}

const dotColors = {
  red: 'bg-accent-red border-accent-red/30',
  orange: 'bg-accent-orange border-accent-orange/30',
  yellow: 'bg-accent-yellow border-accent-yellow/30',
  cyan: 'bg-accent-blue border-accent-blue/30',
  green: 'bg-accent-green border-accent-green/30',
  gray: 'bg-gray-500 border-gray-500/30',
};

export function Timeline({ events, className, animate }: TimelineProps) {
  return (
    <div className={cn('space-y-0', className)}>
      {events.map((event, idx) => (
        <div key={event.id} className={cn('relative flex gap-4 pb-8 last:pb-0', animate && 'animate-fade-in')}>
          <div className="flex flex-col items-center">
            <div
              className={cn(
                'w-3 h-3 rounded-full border-2 shrink-0 mt-1.5',
                dotColors[event.color || 'gray'],
                animate && 'ring-1 ring-accent-blue/30'
              )}
            />
            {idx < events.length - 1 && (
              <div className="w-px flex-1 bg-surface-border mt-1" />
            )}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-gray-500 font-mono">{event.timestamp}</span>
              {event.badge}
            </div>
            <h4 className="text-sm font-medium text-white mt-1">{event.title}</h4>
            {event.description && (
              <p className="text-xs text-gray-400 mt-1">{event.description}</p>
            )}
            {event.icon && <div className="mt-2">{event.icon}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}
