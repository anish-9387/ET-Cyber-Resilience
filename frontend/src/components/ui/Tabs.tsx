'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';

interface Tab {
  key: string;
  label: string;
  icon?: React.ReactNode;
  badge?: React.ReactNode;
  disabled?: boolean;
}

interface TabsProps {
  tabs: Tab[];
  activeKey?: string;
  onChange?: (key: string) => void;
  variant?: 'underline' | 'pills' | 'buttons';
  className?: string;
  tabClassName?: string;
  activeTabClassName?: string;
  children?: React.ReactNode;
}

export function Tabs({
  tabs,
  activeKey: externalActiveKey,
  onChange,
  variant = 'underline',
  className,
  tabClassName,
  activeTabClassName,
  children,
}: TabsProps) {
  const [internalActiveKey, setInternalActiveKey] = useState(tabs[0]?.key || '');
  const isControlled = externalActiveKey !== undefined;
  const activeKey = isControlled ? externalActiveKey : internalActiveKey;

  const handleTabClick = (key: string) => {
    if (!isControlled) setInternalActiveKey(key);
    onChange?.(key);
  };

  const variantStyles = {
    underline:
      'border-b-2 border-transparent text-slate-400 hover:text-white hover:border-slate-500',
    pills:
      'rounded-lg text-slate-400 hover:text-white hover:bg-slate-800',
    buttons:
      'rounded-lg text-slate-400 border border-[#1e293b] hover:text-white hover:bg-slate-800',
  };

  const activeStyles = {
    underline: 'text-cyan-400 border-cyan-500',
    pills: 'text-white bg-cyan-600/20 border border-cyan-600/30',
    buttons: 'text-white bg-cyan-600 border-cyan-600',
  };

  return (
    <div className={className}>
      <div className="flex items-center gap-1">
        {tabs.map((tab) => (
          <button
            key={tab.key}
            disabled={tab.disabled}
            onClick={() => handleTabClick(tab.key)}
            className={cn(
              'flex items-center gap-2 px-4 py-2.5 text-sm font-medium transition-all duration-200',
              variantStyles[variant],
              activeKey === tab.key && activeStyles[variant],
              tab.disabled && 'opacity-50 cursor-not-allowed',
              variant === 'underline' && 'px-1 py-2.5 mx-2',
              variant === 'pills' && 'px-3 py-1.5',
              variant === 'buttons' && 'px-4 py-2',
              tabClassName,
              activeKey === tab.key && activeTabClassName
            )}
          >
            {tab.icon}
            {tab.label}
            {tab.badge}
          </button>
        ))}
      </div>
      {children && (
        <div className="mt-4">
          {Array.isArray(children)
            ? children.find((child: any) => child.props?.tabKey === activeKey)
            : children}
        </div>
      )}
    </div>
  );
}
