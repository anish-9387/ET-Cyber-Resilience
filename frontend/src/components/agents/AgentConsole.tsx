'use client';

import { useState, useRef, useEffect } from 'react';
import { cn } from '@/lib/utils';
import { Button } from '@/components/ui/Button';
import { Search, Filter, Terminal, Download, Trash2, Pause, Play } from 'lucide-react';

interface LogEntry {
  id: string;
  timestamp: string;
  agent: string;
  level: 'info' | 'warn' | 'error' | 'debug';
  message: string;
  details?: string;
}

const mockLogs: LogEntry[] = [
  { id: '1', timestamp: '14:23:45', agent: 'CryptoGuard', level: 'info', message: 'Scan initiated on volume C: (DC-01)', details: 'Scanning 1,247,832 files for ransomware patterns' },
  { id: '2', timestamp: '14:23:42', agent: 'Sentinel', level: 'warn', message: 'Unusual process chain detected on WS-12', details: 'winword.exe → powershell.exe → rundll32.exe' },
  { id: '3', timestamp: '14:23:40', agent: 'NetWatch', level: 'info', message: 'Traffic analysis snapshot complete', details: '12,847 packets analyzed, 0 anomalies' },
  { id: '4', timestamp: '14:23:35', agent: 'ThreatPredictor', level: 'info', message: 'Prediction model refreshed with latest IoCs', details: '3 new indicators added to model v2.4.1' },
  { id: '5', timestamp: '14:23:30', agent: 'Sentinel', level: 'error', message: 'CRITICAL: Credential dumping detected on DC-01', details: 'LSASS memory access by process PID 4521 (wmic.exe)' },
  { id: '6', timestamp: '14:23:28', agent: 'AutoResponder', level: 'info', message: 'Playbook "CredentialTheft_V1" triggered', details: 'Initiating response: isolate DC-01 from network' },
  { id: '7', timestamp: '14:23:25', agent: 'CryptoGuard', level: 'debug', message: 'File system watcher registered on \\\\DC-01\\C$', details: 'Monitoring extensions: .doc, .xls, .pdf, .jpg, .sql' },
  { id: '8', timestamp: '14:23:20', agent: 'NetWatch', level: 'warn', message: 'Suspicious outbound connection detected', details: 'WS-12 → 185.220.101.45:443 (known C2 infrastructure)' },
  { id: '9', timestamp: '14:23:15', agent: 'Sentinel', level: 'info', message: 'Process tree captured for WS-12', details: 'Parent: explorer.exe → child: wmic.exe (suspicious)' },
  { id: '10', timestamp: '14:23:10', agent: 'ThreatPredictor', level: 'info', message: 'Attack path prediction: DC-01 → SQL-01 (72%)', details: 'Based on current TTPs: T1003.001, T1047, T1486' },
];

const levelStyles = {
  error: 'text-accent-red bg-accent-red/5 border-l-accent-red',
  warn: 'text-accent-yellow bg-accent-yellow/5 border-l-accent-yellow',
  info: 'text-gray-300 border-l-accent-cyan',
  debug: 'text-gray-500 border-l-gray-600',
};

const agents = ['All', 'CryptoGuard', 'Sentinel', 'NetWatch', 'ThreatPredictor', 'AutoResponder'];

export function AgentConsole() {
  const [logs, setLogs] = useState(mockLogs);
  const [filterAgent, setFilterAgent] = useState('All');
  const [search, setSearch] = useState('');
  const [paused, setPaused] = useState(false);
  const [autoScroll, setAutoScroll] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);

  const filtered = logs.filter((log) => {
    if (filterAgent !== 'All' && log.agent !== filterAgent) return false;
    if (search && !log.message.toLowerCase().includes(search.toLowerCase()) && !log.agent.toLowerCase().includes(search.toLowerCase())) return false;
    return true;
  });

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = 0;
    }
  }, [filtered, autoScroll]);

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      {/* Header */}
      <div className="px-5 py-3 border-b border-surface-border flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Terminal className="h-5 w-5 text-accent-cyan" />
          <div>
            <h3 className="text-sm font-semibold text-white">Agent Console</h3>
            <p className="text-[10px] text-gray-500 font-mono">{logs.length} log entries</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Button size="sm" variant="ghost" onClick={() => setAutoScroll(!autoScroll)}>
            {autoScroll ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
          </Button>
          <Button size="sm" variant="ghost">
            <Download className="h-3.5 w-3.5" />
          </Button>
          <Button size="sm" variant="ghost">
            <Trash2 className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {/* Filters */}
      <div className="px-5 py-3 border-b border-surface-border flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input
            type="text"
            placeholder="Search logs..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-accent-cyan/50"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <Filter className="h-3 w-3 text-gray-500" />
          {agents.map((agent) => (
            <button
              key={agent}
              onClick={() => setFilterAgent(agent)}
              className={cn(
                'px-2 py-1 text-[10px] rounded font-medium transition-colors whitespace-nowrap',
                filterAgent === agent
                  ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30'
                  : 'text-gray-500 hover:text-white hover:bg-surface-border'
              )}
            >
              {agent}
            </button>
          ))}
        </div>
      </div>

      {/* Log stream */}
      <div ref={scrollRef} className="max-h-[500px] overflow-y-auto font-mono text-xs">
        {filtered.map((log, idx) => (
          <div
            key={log.id}
            className={cn(
              'px-5 py-2 border-l-2 border-b border-surface-border/50 hover:bg-surface/50 transition-colors',
              levelStyles[log.level]
            )}
          >
            <div className="flex items-start gap-3">
              <span className="text-gray-600 shrink-0 w-16">{log.timestamp}</span>
              <span className={cn(
                'shrink-0 w-22 px-1.5 rounded text-center',
                log.agent === 'CryptoGuard' && 'text-accent-green bg-accent-green/10',
                log.agent === 'Sentinel' && 'text-accent-cyan bg-accent-cyan/10',
                log.agent === 'NetWatch' && 'text-blue-400 bg-blue-500/10',
                log.agent === 'ThreatPredictor' && 'text-purple-400 bg-purple-500/10',
                log.agent === 'AutoResponder' && 'text-accent-orange bg-accent-orange/10',
              )}>
                [{log.agent}]
              </span>
              <span className={cn(
                'shrink-0 w-14 uppercase',
                log.level === 'error' && 'text-accent-red',
                log.level === 'warn' && 'text-accent-yellow',
                log.level === 'info' && 'text-gray-400',
                log.level === 'debug' && 'text-gray-600',
              )}>
                {log.level}
              </span>
              <span className="text-gray-300 flex-1">{log.message}</span>
            </div>
            {log.details && (
              <p className="text-gray-600 mt-0.5 ml-[132px]">{log.details}</p>
            )}
          </div>
        ))}
        {filtered.length === 0 && (
          <div className="px-5 py-8 text-center text-sm text-gray-500">No log entries match your search</div>
        )}
      </div>
    </div>
  );
}
