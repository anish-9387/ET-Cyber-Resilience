'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { cn } from '@/lib/utils';
import {
  Shield,
  LayoutDashboard,
  Server,
  AlertTriangle,
  Brain,
  Users,
  BarChart3,
  Settings,
  Bell,
  ChevronLeft,
  ChevronRight,
  Menu,
  X,
  LogOut,
  User,
} from 'lucide-react';
import { StatusIndicator } from '@/components/ui/StatusIndicator';

const navItems = [
  { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { href: '/digital-twin', label: 'Digital Twin', icon: Server },
  { href: '/incidents', label: 'Incidents', icon: AlertTriangle },
  { href: '/threat-intel', label: 'Threat Intel', icon: Brain },
  { href: '/agents', label: 'Agents', icon: Users },
  { href: '/analytics', label: 'Analytics', icon: BarChart3 },
  { href: '/settings', label: 'Settings', icon: Settings },
];

interface DashboardLayoutProps {
  children: React.ReactNode;
}

export function DashboardLayout({ children }: DashboardLayoutProps) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className="flex h-screen bg-surface overflow-hidden">
      {/* Mobile overlay */}
      {mobileOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-40 lg:hidden"
          onClick={() => setMobileOpen(false)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'fixed lg:static inset-y-0 left-0 z-50 flex flex-col bg-surface-card border-r border-surface-border transition-all duration-300',
          collapsed ? 'w-16' : 'w-64',
          mobileOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        )}
      >
        {/* Logo */}
        <div className={cn('flex items-center h-16 px-4 border-b border-surface-border', collapsed && 'justify-center')}>
          <div className="flex items-center gap-3 min-w-0">
            <div className="relative shrink-0">
              <Shield className="h-8 w-8 text-accent-cyan" />
              <div className="absolute -inset-1 bg-accent-cyan/20 rounded-full blur-md" />
            </div>
            {!collapsed && (
              <div className="min-w-0">
                <h1 className="text-lg font-bold text-white truncate">Sentinel-X</h1>
                <p className="text-[10px] text-accent-cyan font-mono">CYBER RESILIENCE</p>
              </div>
            )}
          </div>
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto py-4 px-2 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const active = pathname?.startsWith(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                onClick={() => setMobileOpen(false)}
                className={cn(
                  'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-200',
                  active
                    ? 'bg-accent-cyan/10 text-accent-cyan border border-accent-cyan/20'
                    : 'text-gray-400 hover:text-white hover:bg-surface-border',
                  collapsed && 'justify-center px-2'
                )}
                title={collapsed ? item.label : undefined}
              >
                <Icon className="h-5 w-5 shrink-0" />
                {!collapsed && <span>{item.label}</span>}
                {active && !collapsed && (
                  <div className="ml-auto w-1.5 h-1.5 rounded-full bg-accent-cyan shadow-glow-cyan" />
                )}
              </Link>
            );
          })}
        </nav>

        {/* Collapse toggle */}
        <button
          onClick={() => setCollapsed(!collapsed)}
          className="hidden lg:flex items-center justify-center h-12 border-t border-surface-border text-gray-500 hover:text-white hover:bg-surface-border transition-colors"
        >
          {collapsed ? <ChevronRight className="h-4 w-4" /> : <ChevronLeft className="h-4 w-4" />}
        </button>
      </aside>

      {/* Main content area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Top bar */}
        <header className="flex items-center justify-between h-16 px-4 lg:px-6 bg-surface-card/80 backdrop-blur-md border-b border-surface-border">
          <div className="flex items-center gap-4">
            <button
              onClick={() => setMobileOpen(true)}
              className="lg:hidden p-2 text-gray-400 hover:text-white hover:bg-surface-border rounded-lg transition-colors"
            >
              <Menu className="h-5 w-5" />
            </button>
            <div className="flex items-center gap-2">
              <StatusIndicator status="healthy" size="sm" />
              <span className="text-xs text-gray-400 hidden sm:inline">All systems operational</span>
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Notifications */}
            <button className="relative p-2 text-gray-400 hover:text-white hover:bg-surface-border rounded-lg transition-colors">
              <Bell className="h-5 w-5" />
              <span className="absolute top-1 right-1 w-2 h-2 bg-accent-red rounded-full animate-pulse shadow-glow-red" />
            </button>

            {/* User avatar */}
            <div className="flex items-center gap-3 pl-3 border-l border-surface-border">
              <div className="text-right hidden sm:block">
                <p className="text-sm text-white font-medium">Admin</p>
                <p className="text-[10px] text-gray-500">Security Operations</p>
              </div>
              <div className="relative group">
                <button className="flex items-center gap-2 p-1 rounded-lg hover:bg-surface-border transition-colors">
                  <div className="w-8 h-8 rounded-full bg-accent-cyan/20 border border-accent-cyan/30 flex items-center justify-center">
                    <User className="h-4 w-4 text-accent-cyan" />
                  </div>
                </button>
                {/* Dropdown */}
                <div className="absolute right-0 top-full mt-2 w-48 bg-surface-card border border-surface-border rounded-xl shadow-2xl opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-50">
                  <div className="p-2 space-y-1">
                    <button className="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-surface-border rounded-lg transition-colors">
                      <User className="h-4 w-4" />
                      Profile
                    </button>
                    <button className="w-full flex items-center gap-2 px-3 py-2 text-sm text-gray-300 hover:text-white hover:bg-surface-border rounded-lg transition-colors">
                      <Settings className="h-4 w-4" />
                      Account Settings
                    </button>
                    <hr className="border-surface-border my-1" />
                    <button className="w-full flex items-center gap-2 px-3 py-2 text-sm text-accent-red hover:bg-accent-red/10 rounded-lg transition-colors">
                      <LogOut className="h-4 w-4" />
                      Sign Out
                    </button>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </header>

        {/* Page content */}
        <main className="flex-1 overflow-y-auto p-4 lg:p-6">
          {children}
        </main>
      </div>
    </div>
  );
}
