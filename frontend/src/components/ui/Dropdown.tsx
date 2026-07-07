'use client';

import { useState, useRef, useEffect } from 'react';
import { cn } from '@/lib/utils';
import { ChevronDown } from 'lucide-react';

interface DropdownItem {
  key: string;
  label: string;
  icon?: React.ReactNode;
  divider?: boolean;
  disabled?: boolean;
  danger?: boolean;
}

interface DropdownProps {
  trigger?: React.ReactNode;
  items: DropdownItem[];
  onSelect?: (key: string) => void;
  label?: string;
  align?: 'left' | 'right';
  className?: string;
  menuClassName?: string;
}

export function Dropdown({
  trigger,
  items,
  onSelect,
  label,
  align = 'left',
  className,
  menuClassName,
}: DropdownProps) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    if (open) document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [open]);

  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setOpen(false);
    };
    if (open) document.addEventListener('keydown', handleEscape);
    return () => document.removeEventListener('keydown', handleEscape);
  }, [open]);

  return (
    <div ref={ref} className={cn('relative inline-block', className)}>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-2 px-3 py-2 text-sm text-slate-300 bg-[#111827] border border-[#1e293b] rounded-lg hover:bg-slate-800 hover:text-white transition-colors"
      >
        {trigger || (
          <>
            <span>{label}</span>
            <ChevronDown className={cn('h-4 w-4 transition-transform', open && 'rotate-180')} />
          </>
        )}
      </button>

      {open && (
        <div
          className={cn(
            'absolute z-50 mt-1 min-w-[200px] bg-[#111827] border border-[#1e293b] rounded-xl shadow-2xl py-1',
            align === 'right' ? 'right-0' : 'left-0',
            menuClassName
          )}
        >
          {items.map((item) =>
            item.divider ? (
              <div key={item.key} className="my-1 border-t border-[#1e293b]" />
            ) : (
              <button
                key={item.key}
                disabled={item.disabled}
                onClick={() => {
                  onSelect?.(item.key);
                  setOpen(false);
                }}
                className={cn(
                  'w-full flex items-center gap-2 px-4 py-2 text-sm transition-colors',
                  item.danger
                    ? 'text-red-400 hover:bg-red-500/10'
                    : 'text-slate-300 hover:bg-slate-800 hover:text-white',
                  item.disabled && 'opacity-50 cursor-not-allowed'
                )}
              >
                {item.icon && <span className="h-4 w-4">{item.icon}</span>}
                {item.label}
              </button>
            )
          )}
        </div>
      )}
    </div>
  );
}
