'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { Button } from '@/components/ui/Button';
import { CheckCircle, XCircle, Bell, Filter } from 'lucide-react';

interface Alert {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  timestamp: string;
  mitre: string;
  acknowledged: boolean;
  resolved: boolean;
}

const mockAlerts: Alert[] = [
  { id: 'A-1024', severity: 'critical', title: 'Ransomware Encryption Pattern Detected', description: 'File batch rename and extension change pattern on DC-01 matching known ransomware behavior', timestamp: '2 min ago', mitre: 'T1486', acknowledged: false, resolved: false },
  { id: 'A-1023', severity: 'high', title: 'Lateral Movement via WMI', description: 'WMI execution from WS-12 to SQL-01 with suspicious payload', timestamp: '7 min ago', mitre: 'T1047', acknowledged: false, resolved: false },
  { id: 'A-1022', severity: 'high', title: 'Credential Dumping - LSASS Access', description: 'LSASS process memory opened by non-system process on DC-01', timestamp: '15 min ago', mitre: 'T1003.001', acknowledged: true, resolved: false },
  { id: 'A-1021', severity: 'medium', title: 'Suspicious PowerShell - Encoded Command', description: 'PowerShell executed with -EncodedCommand flag on WS-08', timestamp: '22 min ago', mitre: 'T1059.001', acknowledged: false, resolved: false },
  { id: 'A-1020', severity: 'medium', title: 'Unauthorized Service Installation', description: 'New service Svchost++ installed on WEB-02 by non-admin process', timestamp: '35 min ago', mitre: 'T1543.003', acknowledged: false, resolved: false },
  { id: 'A-1019', severity: 'low', title: 'External Port Scan', description: 'Repeated connection attempts on ports 22,445,3389 from 185.220.101.x', timestamp: '47 min ago', mitre: 'T1046', acknowledged: true, resolved: true },
];

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };

export function AlertsPanel() {
  const [alerts, setAlerts] = useState(mockAlerts);
  const [filter, setFilter] = useState<string>('all');

  const filtered = alerts
    .filter((a) => filter === 'all' || a.severity === filter)
    .sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const handleAcknowledge = (id: string) => {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, acknowledged: true } : a)));
  };

  const handleResolve = (id: string) => {
    setAlerts((prev) => prev.map((a) => (a.id === id ? { ...a, resolved: true, acknowledged: true } : a)));
  };

  const activeCount = alerts.filter((a) => !a.resolved).length;
  const criticalCount = alerts.filter((a) => a.severity === 'critical' && !a.resolved).length;

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b border-surface-border">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="relative">
              <Bell className="h-5 w-5 text-gray-400" />
              {criticalCount > 0 && (
                <span className="absolute -top-1 -right-1 w-2 h-2 bg-accent-red rounded-full animate-pulse" />
              )}
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">Active Alerts</h3>
              <p className="text-[10px] text-gray-500 font-mono">{activeCount} unresolved</p>
            </div>
          </div>
          <div className="flex items-center gap-1">
            <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
            <span className="text-[10px] text-gray-500">Live</span>
          </div>
        </div>

        {/* Filter */}
        <div className="flex items-center gap-1.5">
          <Filter className="h-3 w-3 text-gray-500" />
          {['all', 'critical', 'high', 'medium', 'low'].map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                'px-2 py-1 text-[10px] rounded font-medium transition-colors capitalize',
                filter === f
                  ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30'
                  : 'text-gray-500 hover:text-white hover:bg-surface-border'
              )}
            >
              {f}
            </button>
          ))}
        </div>
      </div>

      <div className="divide-y divide-surface-border max-h-[480px] overflow-y-auto">
        {filtered.map((alert) => (
          <div
            key={alert.id}
            className={cn(
              'px-5 py-3 transition-colors duration-150',
              !alert.acknowledged && alert.severity === 'critical' && 'bg-accent-red/5',
              !alert.acknowledged && alert.severity === 'high' && 'bg-accent-orange/[0.02]',
              alert.resolved && 'opacity-60'
            )}
          >
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 mb-1">
                  <SeverityBadge severity={alert.severity} />
                  <span className="text-[10px] text-gray-500 font-mono">{alert.id}</span>
                  <span className="text-[10px] text-gray-600 bg-surface-border/50 px-1.5 py-0.5 rounded font-mono">
                    {alert.mitre}
                  </span>
                  {!alert.acknowledged && <span className="w-1.5 h-1.5 rounded-full bg-accent-cyan animate-pulse" />}
                </div>
                <h4 className="text-sm font-medium text-white">{alert.title}</h4>
                <p className="text-xs text-gray-400 mt-0.5">{alert.description}</p>
                <p className="text-[10px] text-gray-600 mt-1">{alert.timestamp}</p>
              </div>

              <div className="flex items-center gap-1 shrink-0">
                {!alert.acknowledged && (
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => handleAcknowledge(alert.id)}
                    className="text-accent-cyan hover:text-white"
                  >
                    <CheckCircle className="h-3.5 w-3.5" />
                  </Button>
                )}
                {!alert.resolved && (
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => handleResolve(alert.id)}
                    className="text-accent-green hover:text-white"
                  >
                    <CheckCircle className="h-3.5 w-3.5" />
                  </Button>
                )}
              </div>
            </div>
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="px-5 py-8 text-center text-sm text-gray-500">No alerts match the current filter</div>
        )}
      </div>
    </div>
  );
}
