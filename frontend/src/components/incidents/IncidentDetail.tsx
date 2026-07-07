'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { Timeline } from '@/components/ui/Timeline';
import { Card } from '@/components/ui/Card';
import {
  ArrowLeft,
  Activity,
  FileText,
  Monitor,
  Shield,
  Zap,
  ChevronDown,
  ChevronUp,
  Copy,
  ExternalLink,
} from 'lucide-react';

const incident = {
  id: 'INC-2024-001',
  title: 'Ransomware Attack on DC-01',
  severity: 'critical' as const,
  status: 'contained',
  type: 'Ransomware',
  created: '2024-01-15 14:23 UTC',
  lastUpdated: '2024-01-15 15:47 UTC',
  description: 'Ransomware encryption detected on Domain Controller DC-01. File batch rename and extension change pattern matching known ransomware behavior (BlackCat/ALPHV). Attack originated from compromised workstation WS-12.',
};

const mitreSteps = [
  { id: '1', timestamp: '14:05', title: 'Initial Access — Phishing', description: 'User jdoe@acme opened malicious attachment from spear-phishing email', color: 'cyan' as const, badge: <Badge variant="info" size="sm">T1566</Badge> },
  { id: '2', timestamp: '14:08', title: 'Execution — PowerShell', description: 'Encoded PowerShell command executed on WS-12 for C2 beaconing', color: 'cyan' as const, badge: <Badge variant="info" size="sm">T1059.001</Badge> },
  { id: '3', timestamp: '14:12', title: 'Privilege Escalation', description: 'Local privilege escalation via CVE-2024-1234 on WS-12', color: 'yellow' as const, badge: <Badge variant="warning" size="sm">T1068</Badge> },
  { id: '4', timestamp: '14:18', title: 'Credential Dumping — LSASS', description: 'LSASS memory dumped on DC-01 via WMI from WS-12', color: 'orange' as const, badge: <Badge variant="warning" size="sm">T1003.001</Badge> },
  { id: '5', timestamp: '14:23', title: 'Lateral Movement — WMI', description: 'WMI execution from DC-01 to SQL-01 for credential access', color: 'orange' as const, badge: <Badge variant="warning" size="sm">T1047</Badge> },
  { id: '6', timestamp: '14:28', title: 'Defense Evasion — Impair Defenses', description: 'Windows Defender disabled via registry on DC-01', color: 'red' as const, badge: <Badge variant="danger" size="sm">T1562</Badge> },
  { id: '7', timestamp: '14:35', title: 'Impact — Data Encrypted', description: 'Ransomware encryption initiated on DC-01 file shares (E:, F:)', color: 'red' as const, badge: <Badge variant="danger" size="sm">T1486</Badge> },
];

const evidence = [
  { name: 'LSASS Memory Dump', file: 'lsass_dump_DC-01.dmp', size: '128 MB', type: 'Forensic' },
  { name: 'PowerShell Logs', file: 'powershell_WS-12.evtx', size: '4.2 MB', type: 'Log' },
  { name: 'Network Capture', file: 'pcap_DC-01_14-23.pcapng', size: '847 MB', type: 'Network' },
  { name: 'Memory Snapshot', file: 'mem_DC-01_14-30.raw', size: '16 GB', type: 'Forensic' },
];

const affectedAssets = [
  { name: 'DC-01', ip: '10.0.1.10', impact: 'Critical — Domain Controller' },
  { name: 'WS-12', ip: '10.0.2.12', impact: 'Compromised — Initial Vector' },
  { name: 'SQL-01', ip: '10.0.1.20', impact: 'Targeted — Lateral Movement' },
];

const responseActions = [
  { action: 'Network isolation of DC-01', time: '14:29', status: 'Completed', by: 'AutoResponder' },
  { action: 'Credential rotation for domain admin', time: '14:31', status: 'Completed', by: 'SOC Lead' },
  { action: 'WS-12 quarantine from network', time: '14:33', status: 'Completed', by: 'AutoResponder' },
  { action: 'Full memory capture of DC-01', time: '14:38', status: 'Completed', by: 'Analyst-1' },
  { action: 'Deploy EDR enhanced monitoring on SQL-01', time: '14:42', status: 'In Progress', by: 'Analyst-2' },
];

const aiRecommendations = [
  'Deploy additional honeytokens on SQL-01 to detect further lateral movement attempts',
  'Enable restricted admin mode for RDP on all domain controllers',
  'Implement network micro-segmentation between IT and OT environments',
  'Schedule emergency patching for CVE-2024-1234 on all workstations',
];

export function IncidentDetail() {
  const [showAllTimeline, setShowAllTimeline] = useState(false);
  const displayedSteps = showAllTimeline ? mitreSteps : mitreSteps.slice(-3);

  return (
    <div className="space-y-6">
      {/* Back button & header */}
      <div>
        <button className="flex items-center gap-1 text-xs text-gray-400 hover:text-white transition-colors mb-3">
          <ArrowLeft className="h-3.5 w-3.5" />
          Back to Incidents
        </button>
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3">
              <h2 className="text-xl font-bold text-white">{incident.title}</h2>
              <SeverityBadge severity={incident.severity} size="md" />
            </div>
            <div className="flex items-center gap-3 mt-2">
              <span className="text-xs font-mono text-accent-cyan">{incident.id}</span>
              <span className="text-xs text-gray-500">·</span>
              <span className="text-xs text-gray-400">{incident.type}</span>
              <span className="text-xs text-gray-500">·</span>
              <span className="text-xs text-gray-500">{incident.created}</span>
              <Badge variant={incident.status === 'contained' ? 'warning' : 'default'} size="sm">{incident.status}</Badge>
            </div>
          </div>
          <Button variant="danger" size="sm"><Shield className="h-3.5 w-3.5" /> Escalate</Button>
        </div>
        <p className="text-xs text-gray-400 mt-3 max-w-3xl">{incident.description}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main column */}
        <div className="lg:col-span-2 space-y-6">
          {/* Attack Story Timeline */}
          <Card header={
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-accent-cyan" />
                <h3 className="text-sm font-semibold text-white">Attack Story — MITRE ATT&CK Mapped</h3>
              </div>
              <button
                onClick={() => setShowAllTimeline(!showAllTimeline)}
                className="text-[10px] text-accent-cyan hover:text-cyan-400 transition-colors"
              >
                {showAllTimeline ? 'Show less' : `Show all (${mitreSteps.length} steps)`}
              </button>
            </div>
          }>
            <Timeline events={displayedSteps.map((s) => ({
              id: s.id,
              timestamp: s.timestamp,
              title: s.title,
              description: s.description,
              color: s.color,
              badge: s.badge,
            }))} />
          </Card>

          {/* Evidence */}
          <Card header={
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-accent-cyan" />
              <h3 className="text-sm font-semibold text-white">Evidence Collected</h3>
              <Badge variant="default" size="sm">{evidence.length} items</Badge>
            </div>
          }>
            <div className="divide-y divide-surface-border -mx-5 -mb-5">
              {evidence.map((item) => (
                <div key={item.name} className="px-5 py-3 flex items-center justify-between hover:bg-surface/30 transition-colors">
                  <div className="flex items-center gap-3">
                    <div className="p-1.5 rounded bg-surface text-gray-400">
                      <FileText className="h-4 w-4" />
                    </div>
                    <div>
                      <p className="text-xs text-white font-medium">{item.name}</p>
                      <p className="text-[10px] text-gray-500 font-mono">{item.file} · {item.size}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="default" size="sm">{item.type}</Badge>
                    <button className="p-1 text-gray-500 hover:text-white transition-colors">
                      <Copy className="h-3.5 w-3.5" />
                    </button>
                    <button className="p-1 text-gray-500 hover:text-white transition-colors">
                      <ExternalLink className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </Card>

          {/* AI Recommendations */}
          <Card header={
            <div className="flex items-center gap-2">
              <Zap className="h-4 w-4 text-accent-yellow" />
              <h3 className="text-sm font-semibold text-white">AI Recommendations</h3>
            </div>
          }>
            <div className="space-y-2">
              {aiRecommendations.map((rec, idx) => (
                <div key={idx} className="flex items-start gap-2 px-3 py-2 rounded-lg bg-accent-yellow/5 border border-accent-yellow/10">
                  <div className="w-5 h-5 rounded-full bg-accent-yellow/20 text-accent-yellow flex items-center justify-center shrink-0 mt-0.5">
                    <span className="text-[10px] font-bold">{idx + 1}</span>
                  </div>
                  <p className="text-xs text-gray-300">{rec}</p>
                </div>
              ))}
            </div>
          </Card>
        </div>

        {/* Sidebar */}
        <div className="space-y-4">
          {/* Affected Assets */}
          <Card header={
            <div className="flex items-center gap-2">
              <Monitor className="h-4 w-4 text-accent-red" />
              <h3 className="text-sm font-semibold text-white">Affected Assets</h3>
            </div>
          }>
            <div className="space-y-2 -mx-5 -mb-5">
              {affectedAssets.map((asset) => (
                <div key={asset.name} className="px-5 py-2.5 border-b border-surface-border last:border-b-0">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-white">{asset.name}</span>
                    <span className="text-[10px] text-gray-500 font-mono">{asset.ip}</span>
                  </div>
                  <p className="text-[10px] text-gray-600 mt-0.5">{asset.impact}</p>
                </div>
              ))}
            </div>
          </Card>

          {/* Response Actions */}
          <Card header={
            <div className="flex items-center gap-2">
              <Shield className="h-4 w-4 text-accent-green" />
              <h3 className="text-sm font-semibold text-white">Response Actions</h3>
            </div>
          }>
            <div className="space-y-2 -mx-5 -mb-5">
              {responseActions.map((action, idx) => (
                <div key={idx} className="px-5 py-2.5 border-b border-surface-border last:border-b-0">
                  <div className="flex items-center justify-between">
                    <p className="text-xs text-white">{action.action}</p>
                    <Badge variant={action.status === 'Completed' ? 'success' : 'warning'} size="sm">{action.status}</Badge>
                  </div>
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[10px] text-gray-600 font-mono">{action.time}</span>
                    <span className="text-[10px] text-gray-600">by {action.by}</span>
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
