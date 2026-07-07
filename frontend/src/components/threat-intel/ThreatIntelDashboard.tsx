'use client';

import { cn } from '@/lib/utils';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { MitreMatrix } from './MitreMatrix';
import { ExternalLink, AlertTriangle, Bug, Users, ArrowUpRight, Globe } from 'lucide-react';

interface CVE {
  id: string;
  description: string;
  severity: 'critical' | 'high' | 'medium';
  cvss: number;
  published: string;
  exploited: boolean;
}

interface ThreatActor {
  name: string;
  activity: string;
  lastSeen: string;
  risk: 'critical' | 'high' | 'medium';
  targets: string[];
}

const recentCVEs: CVE[] = [
  { id: 'CVE-2024-1234', description: 'Windows Kerberos authentication bypass allowing privilege escalation', severity: 'critical', cvss: 9.8, published: '2 days ago', exploited: true },
  { id: 'CVE-2024-5678', description: 'Microsoft Exchange Server remote code execution via crafted email', severity: 'high', cvss: 8.5, published: '5 days ago', exploited: true },
  { id: 'CVE-2024-9012', description: 'VMware vCenter Server heap-overflow vulnerability', severity: 'high', cvss: 8.2, published: '1 week ago', exploited: false },
  { id: 'CVE-2024-3456', description: 'Fortinet SSL VPN information disclosure', severity: 'medium', cvss: 6.5, published: '10 days ago', exploited: false },
];

const threatActors: ThreatActor[] = [
  { name: 'APT29 (Cozy Bear)', activity: 'Targeting government networks via spear-phishing', lastSeen: '12 hours ago', risk: 'critical', targets: ['Government', 'Defense'] },
  { name: 'LockBit 3.0', activity: 'Ransomware campaign targeting healthcare sector', lastSeen: '1 day ago', risk: 'high', targets: ['Healthcare', 'Finance'] },
  { name: 'Scattered Spider', activity: 'Social engineering attacks on IT service desks', lastSeen: '3 days ago', risk: 'high', targets: ['Technology', 'Telecom'] },
];

const cisaKEV = [
  { id: 'CVE-2023-34362', product: 'Progress MOVEit Transfer', dueDate: '2024-02-15', remediation: 'Apply patch' },
  { id: 'CVE-2023-2868', product: 'Barracuda ESG', dueDate: '2024-01-30', remediation: 'Replace appliance' },
  { id: 'CVE-2024-1709', product: 'ConnectWise ScreenConnect', dueDate: '2024-03-15', remediation: 'Update to v23.9.8' },
];

export function ThreatIntelDashboard() {
  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-xl font-bold text-white">Threat Intelligence</h2>
        <p className="text-xs text-gray-500 mt-1">MITRE ATT&CK mapping, CVE feeds, and threat actor tracking</p>
      </div>

      {/* Stats bar */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        {[
          { label: 'Active CVEs', value: recentCVEs.length, color: 'text-accent-red', icon: Bug },
          { label: 'Exploited in Wild', value: recentCVEs.filter((c) => c.exploited).length, color: 'text-accent-orange', icon: AlertTriangle },
          { label: 'CISA KEV Alerts', value: cisaKEV.length, color: 'text-accent-yellow', icon: Globe },
          { label: 'Active Threat Actors', value: threatActors.length, color: 'text-accent-cyan', icon: Users },
        ].map((stat) => {
          const Icon = stat.icon;
          return (
            <div key={stat.label} className="bg-surface-card border border-surface-border rounded-xl p-4">
              <div className="flex items-center gap-3">
                <div className={cn('p-2 rounded-lg bg-surface', stat.color)}>
                  <Icon className="h-4 w-4" />
                </div>
                <div>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider">{stat.label}</p>
                  <p className={cn('text-lg font-bold font-mono', stat.color)}>{stat.value}</p>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* MITRE Matrix */}
      <MitreMatrix />

      {/* CVEs & Threat Actors grid */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent CVEs */}
        <Card header={
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold text-white">Recent CVEs</h3>
            <Badge variant="danger" size="sm">{recentCVEs.length} active</Badge>
          </div>
        }>
          <div className="space-y-3 -mx-5 -mb-5">
            {recentCVEs.map((cve) => (
              <div key={cve.id} className="px-5 py-3 border-b border-surface-border last:border-b-0 hover:bg-surface/30 transition-colors">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-mono font-bold text-accent-cyan">{cve.id}</span>
                      <SeverityBadge severity={cve.severity} />
                      {cve.exploited && (
                        <Badge variant="danger" size="sm">Exploited in Wild</Badge>
                      )}
                    </div>
                    <p className="text-xs text-gray-300 mt-1">{cve.description}</p>
                    <div className="flex items-center gap-3 mt-1.5">
                      <span className="text-[10px] text-gray-500 font-mono">CVSS {cve.cvss}</span>
                      <span className="text-[10px] text-gray-600">{cve.published}</span>
                    </div>
                  </div>
                  <a href="#" className="p-1 text-gray-500 hover:text-accent-cyan transition-colors shrink-0">
                    <ExternalLink className="h-3.5 w-3.5" />
                  </a>
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* CISA KEV & Threat Actors */}
        <div className="space-y-4">
          {/* CISA KEV */}
          <Card header={
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-accent-yellow" />
                <h3 className="text-sm font-semibold text-white">CISA KEV Alerts</h3>
              </div>
              <Badge variant="warning" size="sm">Urgent</Badge>
            </div>
          }>
            <div className="space-y-2 -mx-5 -mb-5">
              {cisaKEV.map((kev) => (
                <div key={kev.id} className="px-5 py-2.5 border-b border-surface-border last:border-b-0 flex items-center justify-between">
                  <div>
                    <p className="text-xs font-mono text-accent-cyan font-medium">{kev.id}</p>
                    <p className="text-[10px] text-gray-300">{kev.product}</p>
                    <p className="text-[10px] text-gray-600">Due: {kev.dueDate} · {kev.remediation}</p>
                  </div>
                  <ArrowUpRight className="h-3.5 w-3.5 text-accent-red" />
                </div>
              ))}
            </div>
          </Card>

          {/* Threat Actors */}
          <Card header={
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Users className="h-4 w-4 text-accent-cyan" />
                <h3 className="text-sm font-semibold text-white">Threat Actor Activity</h3>
              </div>
              <Badge variant="info" size="sm">Live Feed</Badge>
            </div>
          }>
            <div className="space-y-2 -mx-5 -mb-5">
              {threatActors.map((actor) => (
                <div key={actor.name} className="px-5 py-2.5 border-b border-surface-border last:border-b-0 hover:bg-surface/30 transition-colors">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={cn(
                        'p-1 rounded',
                        actor.risk === 'critical' ? 'bg-accent-red/20 text-accent-red' : 'bg-accent-orange/20 text-accent-orange'
                      )}>
                        <Users className="h-3 w-3" />
                      </div>
                      <div>
                        <p className="text-xs font-medium text-white">{actor.name}</p>
                        <p className="text-[10px] text-gray-500">{actor.activity}</p>
                      </div>
                    </div>
                    <SeverityBadge severity={actor.risk} />
                  </div>
                  <div className="flex items-center gap-2 mt-1.5">
                    <span className="text-[10px] text-gray-600">Last seen: {actor.lastSeen}</span>
                    {actor.targets.map((t) => (
                      <Badge key={t} variant="default" size="sm">{t}</Badge>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
