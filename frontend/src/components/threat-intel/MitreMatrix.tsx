'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/Badge';
import { X, ChevronDown, ChevronUp, Search } from 'lucide-react';

interface Technique {
  id: string;
  name: string;
  detected: boolean;
  description?: string;
}

interface Tactic {
  id: string;
  name: string;
  techniques: Technique[];
}

const tactics: Tactic[] = [
  {
    id: 'TA0043', name: 'Reconnaissance',
    techniques: [
      { id: 'T1595', name: 'Active Scanning', detected: false },
      { id: 'T1592', name: 'Gather Victim Host Info', detected: true, description: 'Observed scanning for open SMB ports on internal network' },
      { id: 'T1590', name: 'Gather Victim Network Info', detected: false },
    ],
  },
  {
    id: 'TA0001', name: 'Initial Access',
    techniques: [
      { id: 'T1566', name: 'Phishing', detected: true, description: 'Spear-phishing email with malicious attachment detected' },
      { id: 'T1078', name: 'Valid Accounts', detected: false },
      { id: 'T1190', name: 'Exploit Public-Facing App', detected: false },
    ],
  },
  {
    id: 'TA0002', name: 'Execution',
    techniques: [
      { id: 'T1059', name: 'Command and Scripting Interp.', detected: true, description: 'PowerShell encoded command execution on WS-08' },
      { id: 'T1204', name: 'User Execution', detected: false },
      { id: 'T1053', name: 'Scheduled Task/Job', detected: true, description: 'Malicious scheduled task created on DC-01' },
    ],
  },
  {
    id: 'TA0003', name: 'Persistence',
    techniques: [
      { id: 'T1547', name: 'Boot or Logon Autostart', detected: false },
      { id: 'T1505', name: 'Server Software Component', detected: false },
      { id: 'T1136', name: 'Create Account', detected: false },
    ],
  },
  {
    id: 'TA0004', name: 'Privilege Escalation',
    techniques: [
      { id: 'T1548', name: 'Abuse Elevation Control', detected: false },
      { id: 'T1055', name: 'Process Injection', detected: false },
      { id: 'T1068', name: 'Exploitation for Priv Esc', detected: true, description: 'Local privilege escalation via CVE-2024-1234 on WS-12' },
    ],
  },
  {
    id: 'TA0005', name: 'Defense Evasion',
    techniques: [
      { id: 'T1562', name: 'Impair Defenses', detected: true, description: 'Windows Defender disabled via registry on WS-12' },
      { id: 'T1070', name: 'Indicator Removal', detected: false },
      { id: 'T1036', name: 'Masquerading', detected: false },
    ],
  },
  {
    id: 'TA0006', name: 'Credential Access',
    techniques: [
      { id: 'T1003', name: 'OS Credential Dumping', detected: true, description: 'LSASS process memory dumped on DC-01' },
      { id: 'T1555', name: 'Credentials from Password Stores', detected: false },
      { id: 'T1110', name: 'Brute Force', detected: false },
    ],
  },
  {
    id: 'TA0007', name: 'Discovery',
    techniques: [
      { id: 'T1087', name: 'Account Discovery', detected: true, description: 'Net user enumeration via WMI on DC-01' },
      { id: 'T1046', name: 'Network Service Scanning', detected: true, description: 'Port scan detected from WS-12 to SQL-01' },
      { id: 'T1135', name: 'Network Share Discovery', detected: false },
    ],
  },
  {
    id: 'TA0008', name: 'Lateral Movement',
    techniques: [
      { id: 'T1021', name: 'Remote Services', detected: true, description: 'WMI execution from DC-01 to SQL-01' },
      { id: 'T1570', name: 'Lateral Tool Transfer', detected: true, description: 'PsExec used to copy tools from DC-01 to WS-12' },
      { id: 'T1550', name: 'Use Alternate Auth Material', detected: false },
    ],
  },
  {
    id: 'TA0009', name: 'Collection',
    techniques: [
      { id: 'T1005', name: 'Data from Local System', detected: false },
      { id: 'T1074', name: 'Data Staged', detected: false },
      { id: 'T1560', name: 'Archive Collected Data', detected: true, description: 'Files compressed to .zip on SQL-01 before exfil' },
    ],
  },
  {
    id: 'TA0040', name: 'Impact',
    techniques: [
      { id: 'T1486', name: 'Data Encrypted for Impact', detected: true, description: 'Ransomware encryption detected on DC-01 file shares' },
      { id: 'T1490', name: 'Inhibit System Recovery', detected: true, description: 'Shadow copies deleted on DC-01 and SQL-01' },
      { id: 'T1485', name: 'Data Destruction', detected: false },
    ],
  },
];

export function MitreMatrix() {
  const [selected, setSelected] = useState<Technique | null>(null);
  const [search, setSearch] = useState('');

  const filteredTactics = search
    ? tactics
        .map((t) => ({
          ...t,
          techniques: t.techniques.filter(
            (tech) =>
              tech.name.toLowerCase().includes(search.toLowerCase()) ||
              tech.id.toLowerCase().includes(search.toLowerCase())
          ),
        }))
        .filter((t) => t.techniques.length > 0)
    : tactics;

  const detectedCount = tactics.reduce((sum, t) => sum + t.techniques.filter((tech) => tech.detected).length, 0);

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b border-surface-border">
        <div className="flex items-center justify-between mb-3">
          <div>
            <h3 className="text-sm font-semibold text-white">MITRE ATT&CK Matrix</h3>
            <p className="text-[10px] text-gray-500 font-mono">{detectedCount} techniques detected</p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant="danger" size="sm">{detectedCount} Active</Badge>
            <Badge variant="default" size="sm">{tactics.length} Tactics</Badge>
          </div>
        </div>
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input
            type="text"
            placeholder="Search techniques by name or ID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-accent-cyan/50"
          />
        </div>
      </div>

      {/* Matrix grid */}
      <div className="overflow-x-auto">
        <div className="flex gap-1 p-3 min-w-max">
          {filteredTactics.map((tactic) => (
            <div key={tactic.id} className="flex flex-col gap-1 min-w-[120px] max-w-[140px]">
              {/* Tactic header */}
              <div className="px-2 py-1.5 rounded bg-surface border border-surface-border text-center">
                <p className="text-[9px] text-gray-500 font-mono">{tactic.id}</p>
                <p className="text-[10px] text-white font-medium leading-tight">{tactic.name}</p>
              </div>

              {/* Technique cells */}
              {tactic.techniques.map((tech) => (
                <button
                  key={tech.id}
                  onClick={() => setSelected(selected?.id === tech.id ? null : tech)}
                  className={cn(
                    'px-2 py-2 rounded text-[9px] leading-tight text-left border transition-all duration-150',
                    tech.detected
                      ? 'bg-accent-red/10 border-accent-red/40 text-accent-red hover:bg-accent-red/20'
                      : 'bg-surface/50 border-surface-border text-gray-500 hover:border-gray-500/50 hover:text-gray-300'
                  )}
                >
                  <span className="font-mono">{tech.id}</span>
                  <br />
                  {tech.name}
                  {tech.detected && <span className="ml-1 text-[8px]">●</span>}
                </button>
              ))}
            </div>
          ))}
        </div>
      </div>

      {/* Detail panel */}
      {selected && (
        <div className="border-t border-surface-border px-5 py-4">
          <div className="flex items-start gap-4">
            <div className="flex-1">
              <div className="flex items-center gap-2 mb-2">
                <Badge variant={selected.detected ? 'danger' : 'default'} size="sm">
                  {selected.detected ? 'DETECTED' : 'NOT DETECTED'}
                </Badge>
                <span className="text-xs font-mono text-accent-cyan">{selected.id}</span>
                <span className="text-xs text-white font-medium">{selected.name}</span>
              </div>
              {selected.description && (
                <p className="text-xs text-gray-400">{selected.description}</p>
              )}
            </div>
            <button
              onClick={() => setSelected(null)}
              className="p-1 text-gray-400 hover:text-white hover:bg-surface-border rounded transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
