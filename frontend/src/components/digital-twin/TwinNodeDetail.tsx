'use client';

import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { X, Server, Monitor, Shield, Database, Wifi, Activity, ArrowRight, Play } from 'lucide-react';

interface TwinNodeData {
  id: string;
  label: string;
  type: string;
  status: 'healthy' | 'degraded' | 'compromised' | 'recovering';
  ip: string;
  risk: number;
}

const connectedAssets = [
  { id: 'ws-12', label: 'WS-12', type: 'Workstation', risk: 88 },
  { id: 'ws-08', label: 'WS-08', type: 'Workstation', risk: 45 },
  { id: 'fw-1', label: 'Firewall', type: 'Network', risk: 5 },
];

const recentEvents = [
  { time: '2 min ago', event: 'LSASS memory access detected', severity: 'critical' as const },
  { time: '8 min ago', event: 'Suspicious scheduled task created', severity: 'high' as const },
  { time: '15 min ago', event: 'Unusual network connection to 10.0.2.12', severity: 'medium' as const },
];

const attackPaths = [
  { from: 'Firewall', to: 'DC-01', probability: '87%', mitre: 'T1047' },
  { from: 'DC-01', to: 'SQL-01', probability: '72%', mitre: 'T1486' },
];

const typeIcons: Record<string, React.ReactNode> = {
  Server: <Server className="h-4 w-4" />,
  Database: <Database className="h-4 w-4" />,
  Workstation: <Monitor className="h-4 w-4" />,
  Network: <Wifi className="h-4 w-4" />,
  Firewall: <Shield className="h-4 w-4" />,
};

interface TwinNodeDetailProps {
  node: TwinNodeData;
  onClose: () => void;
}

export function TwinNodeDetail({ node, onClose }: TwinNodeDetailProps) {
  const riskColor = node.risk > 70 ? 'text-accent-red' : node.risk > 40 ? 'text-accent-yellow' : 'text-accent-green';

  return (
    <div className="bg-surface-card/95 backdrop-blur-md border border-surface-border rounded-xl shadow-2xl max-h-[560px] overflow-y-auto">
      <div className="flex items-center justify-between px-4 py-3 border-b border-surface-border sticky top-0 bg-surface-card/95 backdrop-blur-md z-10">
        <div className="flex items-center gap-2">
          <div className={cn(
            'p-1.5 rounded',
            node.type === 'Server' && 'bg-blue-500/20 text-blue-400',
            node.type === 'Database' && 'bg-purple-500/20 text-purple-400',
            node.type === 'Workstation' && 'bg-gray-500/20 text-gray-300',
            node.type === 'Network' && 'bg-green-500/20 text-green-400',
            node.type === 'Firewall' && 'bg-accent-cyan/20 text-accent-cyan',
          )}>
            {typeIcons[node.type] || <Activity className="h-4 w-4" />}
          </div>
          <div>
            <h4 className="text-sm font-semibold text-white">{node.label}</h4>
            <p className="text-[10px] text-gray-500">{node.type}</p>
          </div>
        </div>
        <button onClick={onClose} className="p-1 text-gray-400 hover:text-white hover:bg-surface-border rounded transition-colors">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="p-4 space-y-4">
        {/* Status & IP */}
        <div className="grid grid-cols-2 gap-3">
          <div className="px-3 py-2 rounded-lg bg-surface/50">
            <p className="text-[10px] text-gray-500 mb-0.5">Status</p>
            <Badge
              variant={
                node.status === 'compromised' ? 'danger' :
                node.status === 'degraded' ? 'warning' :
                node.status === 'healthy' ? 'success' : 'info'
              }
              size="sm"
            >
              {node.status}
            </Badge>
          </div>
          <div className="px-3 py-2 rounded-lg bg-surface/50">
            <p className="text-[10px] text-gray-500 mb-0.5">IP Address</p>
            <p className="text-xs text-white font-mono">{node.ip}</p>
          </div>
        </div>

        {/* Risk Score */}
        <div>
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs text-gray-400">Risk Score</span>
            <span className={cn('text-sm font-bold font-mono', riskColor)}>{node.risk}%</span>
          </div>
          <div className="h-1.5 bg-surface rounded-full overflow-hidden">
            <div
              className={cn(
                'h-full rounded-full transition-all',
                node.risk > 70 ? 'bg-accent-red' : node.risk > 40 ? 'bg-accent-yellow' : 'bg-accent-green'
              )}
              style={{ width: `${node.risk}%` }}
            />
          </div>
        </div>

        {/* Connected Assets */}
        <div>
          <p className="text-xs text-gray-400 font-medium mb-2">Connected Assets</p>
          <div className="space-y-1.5">
            {connectedAssets.map((asset) => (
              <div key={asset.id} className="flex items-center gap-2 px-2.5 py-1.5 rounded-lg bg-surface/50 hover:bg-surface-border transition-colors cursor-pointer">
                <div className="p-1 rounded bg-surface text-gray-400">
                  <Monitor className="h-3 w-3" />
                </div>
                <span className="text-xs text-white flex-1">{asset.label}</span>
                <span className={cn(
                  'text-[10px] font-mono font-medium',
                  asset.risk > 70 ? 'text-accent-red' : asset.risk > 40 ? 'text-accent-yellow' : 'text-accent-green'
                )}>
                  {asset.risk}%
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Recent Events */}
        <div>
          <p className="text-xs text-gray-400 font-medium mb-2">Recent Events</p>
          <div className="space-y-1.5">
            {recentEvents.map((evt, idx) => (
              <div key={idx} className="flex items-start gap-2 text-xs">
                <div className={cn(
                  'w-1.5 h-1.5 rounded-full mt-1.5 shrink-0',
                  evt.severity === 'critical' ? 'bg-accent-red' :
                  evt.severity === 'high' ? 'bg-accent-orange' :
                  evt.severity === 'medium' ? 'bg-accent-yellow' : 'bg-accent-cyan'
                )} />
                <div className="min-w-0 flex-1">
                  <p className="text-gray-300">{evt.event}</p>
                  <p className="text-[10px] text-gray-600">{evt.time}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Attack Paths */}
        <div>
          <p className="text-xs text-gray-400 font-medium mb-2">Predicted Attack Paths</p>
          <div className="space-y-1.5">
            {attackPaths.map((path, idx) => (
              <div key={idx} className="flex items-center gap-2 px-2.5 py-2 rounded-lg bg-accent-red/5 border border-accent-red/10">
                <span className="text-[10px] text-gray-500 font-mono">{path.mitre}</span>
                <span className="text-xs text-gray-300">{path.from}</span>
                <ArrowRight className="h-3 w-3 text-accent-red" />
                <span className="text-xs text-gray-300">{path.to}</span>
                <span className="ml-auto text-[10px] text-accent-red font-mono">{path.probability}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Response Actions */}
        <div className="pt-2">
          <p className="text-xs text-gray-400 font-medium mb-2">Response Actions</p>
          <div className="grid grid-cols-2 gap-2">
            <Button size="sm" variant="danger">
              <Shield className="h-3.5 w-3.5" />
              Isolate
            </Button>
            <Button size="sm" variant="secondary">
              <Activity className="h-3.5 w-3.5" />
              Scan
            </Button>
            <Button size="sm" variant="secondary" className="col-span-2">
              <Play className="h-3.5 w-3.5" />
              Run Automated Response
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
