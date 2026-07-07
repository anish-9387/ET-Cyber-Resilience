'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { StatusIndicator } from '@/components/ui/StatusIndicator';
import { Bot, Activity, CheckCircle, XCircle, ToggleLeft, ToggleRight, ChevronDown, ChevronUp } from 'lucide-react';

interface Agent {
  id: string;
  name: string;
  type: string;
  status: 'active' | 'idle' | 'error';
  lastRun: string;
  metrics: { runs: number; successes: number; failures: number };
  enabled: boolean;
  recentLog: { time: string; message: string; level: 'info' | 'warn' | 'error' }[];
}

const mockAgents: Agent[] = [
  {
    id: 'cryptoguard',
    name: 'CryptoGuard',
    type: 'Detection',
    status: 'active',
    lastRun: '30s ago',
    metrics: { runs: 1247, successes: 1198, failures: 49 },
    enabled: true,
    recentLog: [
      { time: '30s ago', message: 'Scan complete — no ransomware patterns', level: 'info' },
      { time: '2m ago', message: 'Monitoring file system events on DC-01', level: 'info' },
      { time: '5m ago', message: 'Suspicious batch rename detected (FP dismissed)', level: 'warn' },
    ],
  },
  {
    id: 'sentinel',
    name: 'Sentinel',
    type: 'EDR',
    status: 'active',
    lastRun: '15s ago',
    metrics: { runs: 3421, successes: 3356, failures: 65 },
    enabled: true,
    recentLog: [
      { time: '15s ago', message: 'Process tree analysis complete', level: 'info' },
      { time: '1m ago', message: 'LSASS access alert — credential dumping detected', level: 'error' },
    ],
  },
  {
    id: 'netwatch',
    name: 'NetWatch',
    type: 'Network',
    status: 'idle',
    lastRun: '3m ago',
    metrics: { runs: 892, successes: 874, failures: 18 },
    enabled: true,
    recentLog: [
      { time: '3m ago', message: 'Traffic analysis complete — no anomalies', level: 'info' },
    ],
  },
  {
    id: 'threatpredictor',
    name: 'ThreatPredictor',
    type: 'AI/ML',
    status: 'active',
    lastRun: '10s ago',
    metrics: { runs: 567, successes: 543, failures: 24 },
    enabled: true,
    recentLog: [
      { time: '10s ago', message: 'Prediction: Lateral movement to SQL-01 (87%)', level: 'info' },
      { time: '2m ago', message: 'Model updated — new IoC patterns loaded', level: 'info' },
    ],
  },
  {
    id: 'responder',
    name: 'AutoResponder',
    type: 'Response',
    status: 'error',
    lastRun: '12m ago',
    metrics: { runs: 234, successes: 210, failures: 24 },
    enabled: false,
    recentLog: [
      { time: '12m ago', message: 'Playbook execution failed — API timeout', level: 'error' },
      { time: '15m ago', message: 'Isolation action triggered on WS-12', level: 'info' },
    ],
  },
];

export function AgentStatusPanel() {
  const [agents, setAgents] = useState(mockAgents);
  const [expanded, setExpanded] = useState<string | null>(null);

  const toggleAgent = (id: string) => {
    setAgents((prev) => prev.map((a) => (a.id === id ? { ...a, enabled: !a.enabled } : a)));
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-white">AI Agents</h3>
        <div className="flex items-center gap-2">
          <StatusIndicator status="active" size="sm" />
          <span className="text-[10px] text-gray-500">{agents.filter((a) => a.status === 'active').length} active</span>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {agents.map((agent) => (
          <Card
            key={agent.id}
            className={cn(
              'transition-all duration-200',
              !agent.enabled && 'opacity-60',
              agent.status === 'active' && 'border-accent-green/20',
              agent.status === 'error' && 'border-accent-red/30'
            )}
          >
            <div className="flex items-start gap-3">
              <div className={cn(
                'p-2 rounded-lg shrink-0',
                agent.status === 'active' ? 'bg-accent-green/10 text-accent-green' :
                agent.status === 'error' ? 'bg-accent-red/10 text-accent-red' :
                'bg-gray-500/10 text-gray-400'
              )}>
                <Bot className="h-5 w-5" />
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <h4 className="text-sm font-semibold text-white">{agent.name}</h4>
                  <Badge variant={
                    agent.status === 'active' ? 'success' :
                    agent.status === 'error' ? 'danger' : 'default'
                  } size="sm">
                    {agent.status}
                  </Badge>
                </div>
                <p className="text-[10px] text-gray-500 mt-0.5">{agent.type} · Last run: {agent.lastRun}</p>

                {/* Metrics */}
                <div className="flex items-center gap-4 mt-2">
                  <div className="flex items-center gap-1">
                    <Activity className="h-3 w-3 text-accent-cyan" />
                    <span className="text-[10px] text-gray-400 font-mono">{agent.metrics.runs}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <CheckCircle className="h-3 w-3 text-accent-green" />
                    <span className="text-[10px] text-gray-400 font-mono">{agent.metrics.successes}</span>
                  </div>
                  <div className="flex items-center gap-1">
                    <XCircle className="h-3 w-3 text-accent-red" />
                    <span className="text-[10px] text-gray-400 font-mono">{agent.metrics.failures}</span>
                  </div>
                  <div className="ml-auto">
                    <span className="text-[10px] text-gray-600 font-mono">
                      {((agent.metrics.successes / agent.metrics.runs) * 100).toFixed(1)}% success
                    </span>
                  </div>
                </div>
              </div>

              <div className="flex flex-col items-center gap-1">
                <button
                  onClick={() => toggleAgent(agent.id)}
                  className={cn(
                    'p-1 rounded transition-colors',
                    agent.enabled ? 'text-accent-green hover:text-accent-green/80' : 'text-gray-600 hover:text-gray-400'
                  )}
                >
                  {agent.enabled ? <ToggleRight className="h-5 w-5" /> : <ToggleLeft className="h-5 w-5" />}
                </button>
                <button
                  onClick={() => setExpanded(expanded === agent.id ? null : agent.id)}
                  className="p-1 text-gray-500 hover:text-white transition-colors"
                >
                  {expanded === agent.id ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Expanded log */}
            {expanded === agent.id && (
              <div className="mt-3 pt-3 border-t border-surface-border">
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-2">Recent Activity</p>
                <div className="space-y-1 max-h-32 overflow-y-auto">
                  {agent.recentLog.map((log, idx) => (
                    <div key={idx} className="flex items-start gap-2 text-[10px]">
                      <span className={cn(
                        'w-1 h-1 rounded-full mt-1.5 shrink-0',
                        log.level === 'error' ? 'bg-accent-red' :
                        log.level === 'warn' ? 'bg-accent-yellow' : 'bg-accent-cyan'
                      )} />
                      <span className="text-gray-600 font-mono shrink-0">{log.time}</span>
                      <span className={cn(
                        'font-mono',
                        log.level === 'error' ? 'text-accent-red' :
                        log.level === 'warn' ? 'text-accent-yellow' : 'text-gray-300'
                      )}>{log.message}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>
        ))}
      </div>
    </div>
  );
}
