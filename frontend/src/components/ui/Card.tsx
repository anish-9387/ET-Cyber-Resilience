import { cn } from '@/lib/utils';

interface CardProps {
  className?: string;
  children: React.ReactNode;
  header?: React.ReactNode;
  footer?: React.ReactNode;
  hover?: boolean;
}

export function Card({ className, children, header, footer, hover }: CardProps) {
  return (
    <div
      className={cn(
        'bg-surface-card border border-surface-border rounded-xl overflow-hidden',
        hover && 'hover:border-accent-blue/30 transition-colors duration-200',
        className
      )}
    >
      {header && (
        <div className="px-5 py-4 border-b border-surface-border">
          {header}
        </div>
      )}
      <div className="p-5">{children}</div>
      {footer && (
        <div className="px-5 py-3 border-t border-surface-border bg-surface/50">
          {footer}
        </div>
      )}
    </div>
  );
}
