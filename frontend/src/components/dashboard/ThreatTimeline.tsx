'use client';

import { useEffect, useRef } from 'react';
import { cn } from '@/lib/utils';
import { Timeline } from '@/components/ui/Timeline';

interface ThreatEvent {
  id: string;
  timestamp: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  mitreTechnique: string;
}

const mockEvents: ThreatEvent[] = [
  { id: '1', timestamp: '2024-01-15T14:23:00Z', severity: 'critical', title: 'Ransomware Encryption Detected', description: 'File encryption activity detected on DC-01 by CryptoGuard agent', mitreTechnique: 'T1486' },
  { id: '2', timestamp: '2024-01-15T14:18:00Z', severity: 'high', title: 'Lateral Movement via WMI', description: 'WMI process creation from WORKSTATION-12 to SQL-01', mitreTechnique: 'T1047' },
  { id: '3', timestamp: '2024-01-15T14:12:00Z', severity: 'medium', title: 'Suspicious PowerShell Execution', description: 'Encoded PowerShell command detected on WORKSTATION-08', mitreTechnique: 'T1059.001' },
  { id: '4', timestamp: '2024-01-15T14:05:00Z', severity: 'high', title: 'Credential Dumping Attempt', description: 'LSASS memory access detected on DC-01 by Sentinel agent', mitreTechnique: 'T1003.001' },
  { id: '5', timestamp: '2024-01-15T13:55:00Z', severity: 'low', title: 'Port Scan Detected', description: 'Repeated connection attempts from external IP 185.220.101.x', mitreTechnique: 'T1046' },
  { id: '6', timestamp: '2024-01-15T13:48:00Z', severity: 'medium', title: 'New Service Installed', description: 'Unauthorized service Svchost++ installed on WEB-02', mitreTechnique: 'T1543.003' },
];

const severityColors = {
  critical: 'red',
  high: 'orange',
  medium: 'yellow',
  low: 'cyan',
} as const;

function severityBadge(severity: ThreatEvent['severity']) {
  const styles = {
    critical: 'bg-accent-red/20 text-accent-red border-accent-red/30',
    high: 'bg-accent-orange/20 text-accent-orange border-accent-orange/30',
    medium: 'bg-accent-yellow/20 text-accent-yellow border-accent-yellow/30',
    low: 'bg-accent-cyan/20 text-accent-cyan border-accent-cyan/30',
  };
  return (
    <span className={cn('text-[10px] px-1.5 py-0.5 rounded border font-medium', styles[severity])}>
      {severity.toUpperCase()}
    </span>
  );
}

export function ThreatTimeline() {
  const scrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, []);

  const events = mockEvents.map((e) => ({
    id: e.id,
    timestamp: new Date(e.timestamp).toLocaleTimeString(),
    title: e.title,
    description: e.description,
    color: severityColors[e.severity],
    badge: (
      <div className="flex items-center gap-1.5">
        {severityBadge(e.severity)}
        <span className="text-[10px] text-gray-500 font-mono bg-surface-border/50 px-1.5 py-0.5 rounded">
          {e.mitreTechnique}
        </span>
      </div>
    ),
  }));

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-semibold text-white">Real-Time Threat Timeline</h3>
        <div className="flex items-center gap-2">
          <span className="w-1.5 h-1.5 rounded-full bg-accent-green animate-pulse" />
          <span className="text-[10px] text-gray-500 font-mono">LIVE</span>
        </div>
      </div>
      <div ref={scrollRef} className="max-h-[400px] overflow-y-auto custom-scrollbar">
        <Timeline events={events} animate />
      </div>
    </div>
  );
}
