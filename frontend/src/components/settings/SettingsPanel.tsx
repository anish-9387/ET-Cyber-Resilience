'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import {
  Bell,
  Save,
  RefreshCw,
  Sliders,
  Globe,
  Shield,
  Key,
  ChevronDown,
  ChevronUp,
  Eye,
  EyeOff,
  Plus,
  Trash2,
  CheckCircle,
  XCircle,
} from 'lucide-react';

interface Webhook {
  id: string;
  channel: string;
  url: string;
  enabled: boolean;
  events: string[];
}

interface ApiKey {
  id: string;
  name: string;
  key: string;
  createdAt: string;
  lastUsed: string;
  enabled: boolean;
}

const initialWebhooks: Webhook[] = [
  { id: '1', channel: 'Slack', url: 'https://hooks.slack.com/services/xxx', enabled: true, events: ['critical', 'high'] },
  { id: '2', channel: 'Email', url: 'smtp://soc@acme.com', enabled: true, events: ['critical'] },
  { id: '3', channel: 'Microsoft Teams', url: 'https://outlook.office.com/webhook/xxx', enabled: false, events: ['critical', 'high', 'medium'] },
];

const initialApiKeys: ApiKey[] = [
  { id: '1', name: 'SIEM Integration', key: 'sx_pk_xxxxxxxxxxxx...', createdAt: '2024-01-01', lastUsed: '2024-01-15 14:23', enabled: true },
  { id: '2', name: 'SOAR Playbook', key: 'sx_pk_yyyyyyyyyy...', createdAt: '2024-01-05', lastUsed: '2024-01-14 09:15', enabled: true },
  { id: '3', name: 'API Lab Test', key: 'sx_pk_zzzzzzzzzz...', createdAt: '2024-01-10', lastUsed: '2024-01-12 16:30', enabled: false },
];

const intelSources = [
  { name: 'MITRE ATT&CK', status: 'connected', lastSync: '2 min ago' },
  { name: 'CISA KEV', status: 'connected', lastSync: '15 min ago' },
  { name: 'AlienVault OTX', status: 'connected', lastSync: '1 hour ago' },
  { name: 'VirusTotal', status: 'disconnected', lastSync: 'never' },
  { name: 'MISP Instance', status: 'connected', lastSync: '5 min ago' },
];

const automationLevels = [
  { level: 'Level 1 — Manual', description: 'All actions require human approval' },
  { level: 'Level 2 — Semi-Automated', description: 'Containment actions auto-approved, remediation requires approval' },
  { level: 'Level 3 — Automated', description: 'Containment and standard remediation auto-approved' },
  { level: 'Level 4 — Full Automation', description: 'All response actions executed automatically (AI-supervised)' },
];

export function SettingsPanel() {
  const [webhooks, setWebhooks] = useState(initialWebhooks);
  const [apiKeys, setApiKeys] = useState(initialApiKeys);
  const [showKey, setShowKey] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const [automationLevel, setAutomationLevel] = useState(2);
  const [expandedSection, setExpandedSection] = useState<string | null>('general');

  const toggleSection = (section: string) => {
    setExpandedSection(expandedSection === section ? null : section);
  };

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white">System Settings</h2>
          <p className="text-xs text-gray-500 mt-1">Configure Sentinel-X platform</p>
        </div>
        <Button onClick={handleSave} variant="primary" size="sm" icon={saved ? <CheckCircle className="h-4 w-4" /> : <Save className="h-4 w-4" />}>
          {saved ? 'Saved' : 'Save Changes'}
        </Button>
      </div>

      <div className="space-y-3">
        {/* General */}
        <Card>
          <button
            onClick={() => toggleSection('general')}
            className="w-full flex items-center justify-between"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-accent-cyan/10 text-accent-cyan">
                <Sliders className="h-4 w-4" />
              </div>
              <div className="text-left">
                <h3 className="text-sm font-semibold text-white">General Settings</h3>
                <p className="text-[10px] text-gray-500">System name, refresh intervals, display options</p>
              </div>
            </div>
            {expandedSection === 'general' ? <ChevronUp className="h-4 w-4 text-gray-400" /> : <ChevronDown className="h-4 w-4 text-gray-400" />}
          </button>
          {expandedSection === 'general' && (
            <div className="mt-4 pt-4 border-t border-surface-border space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <div>
                  <label className="text-xs text-gray-400 block mb-1">System Name</label>
                  <input
                    type="text"
                    defaultValue="Sentinel-X"
                    className="w-full px-3 py-2 text-xs bg-surface border border-surface-border rounded-lg text-white focus:outline-none focus:border-accent-cyan/50"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 block mb-1">Dashboard Refresh Interval</label>
                  <select className="w-full px-3 py-2 text-xs bg-surface border border-surface-border rounded-lg text-gray-300 focus:outline-none focus:border-accent-cyan/50">
                    <option>10 seconds</option>
                    <option>30 seconds</option>
                    <option>1 minute</option>
                    <option>5 minutes</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs text-gray-400 block mb-1">Data Retention (days)</label>
                  <input
                    type="number"
                    defaultValue={90}
                    className="w-full px-3 py-2 text-xs bg-surface border border-surface-border rounded-lg text-white focus:outline-none focus:border-accent-cyan/50"
                  />
                </div>
                <div>
                  <label className="text-xs text-gray-400 block mb-1">Max Alert Display</label>
                  <input
                    type="number"
                    defaultValue={100}
                    className="w-full px-3 py-2 text-xs bg-surface border border-surface-border rounded-lg text-white focus:outline-none focus:border-accent-cyan/50"
                  />
                </div>
              </div>
            </div>
          )}
        </Card>

        {/* Notification Channels */}
        <Card>
          <button
            onClick={() => toggleSection('notifications')}
            className="w-full flex items-center justify-between"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-accent-yellow/10 text-accent-yellow">
                <Bell className="h-4 w-4" />
              </div>
              <div className="text-left">
                <h3 className="text-sm font-semibold text-white">Notification Channels</h3>
                <p className="text-[10px] text-gray-500">Slack, Email, Teams webhooks</p>
              </div>
            </div>
            {expandedSection === 'notifications' ? <ChevronUp className="h-4 w-4 text-gray-400" /> : <ChevronDown className="h-4 w-4 text-gray-400" />}
          </button>
          {expandedSection === 'notifications' && (
            <div className="mt-4 pt-4 border-t border-surface-border space-y-3">
              {webhooks.map((wh) => (
                <div key={wh.id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-surface/50">
                  <div className="p-1.5 rounded bg-surface text-gray-400">
                    <Bell className="h-4 w-4" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-white">{wh.channel}</span>
                      <Badge variant={wh.enabled ? 'success' : 'default'} size="sm">{wh.enabled ? 'Enabled' : 'Disabled'}</Badge>
                    </div>
                    <p className="text-[10px] text-gray-500 font-mono truncate mt-0.5">{wh.url}</p>
                    <div className="flex items-center gap-1 mt-1">
                      {wh.events.map((evt) => (
                        <Badge key={evt} variant={
                          evt === 'critical' ? 'danger' : evt === 'high' ? 'warning' : 'info'
                        } size="sm">{evt}</Badge>
                      ))}
                    </div>
                  </div>
                  <button className="p-1 text-gray-500 hover:text-accent-red transition-colors">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
              <Button size="sm" variant="secondary" icon={<Plus className="h-3.5 w-3.5" />}>
                Add Webhook
              </Button>
            </div>
          )}
        </Card>

        {/* Agent Configuration */}
        <Card>
          <button
            onClick={() => toggleSection('agents')}
            className="w-full flex items-center justify-between"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-accent-green/10 text-accent-green">
                <Shield className="h-4 w-4" />
              </div>
              <div className="text-left">
                <h3 className="text-sm font-semibold text-white">Agent Configuration</h3>
                <p className="text-[10px] text-gray-500">AI agent enable/disable, scheduling, thresholds</p>
              </div>
            </div>
            {expandedSection === 'agents' ? <ChevronUp className="h-4 w-4 text-gray-400" /> : <ChevronDown className="h-4 w-4 text-gray-400" />}
          </button>
          {expandedSection === 'agents' && (
            <div className="mt-4 pt-4 border-t border-surface-border space-y-4">
              {['CryptoGuard', 'Sentinel', 'NetWatch', 'ThreatPredictor', 'AutoResponder'].map((agent) => (
                <div key={agent} className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface/50">
                  <div>
                    <p className="text-xs font-medium text-white">{agent}</p>
                    <p className="text-[10px] text-gray-500">Run interval: 30s · Threshold: Medium</p>
                  </div>
                  <div className="flex items-center gap-2">
                    <select className="px-2 py-1 text-[10px] bg-surface border border-surface-border rounded text-gray-300">
                      <option>Every 10s</option>
                      <option>Every 30s</option>
                      <option>Every 60s</option>
                    </select>
                    <label className="relative inline-flex items-center cursor-pointer">
                      <input type="checkbox" defaultChecked className="sr-only peer" />
                      <div className="w-8 h-4 bg-surface rounded-full peer peer-checked:bg-accent-green after:content-[''] after:absolute after:top-0.5 after:left-0.5 after:bg-white after:rounded-full after:h-3 after:w-3 after:transition-all peer-checked:after:translate-x-4" />
                    </label>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Card>

        {/* Threat Intel Sources */}
        <Card>
          <button
            onClick={() => toggleSection('intel')}
            className="w-full flex items-center justify-between"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400">
                <Globe className="h-4 w-4" />
              </div>
              <div className="text-left">
                <h3 className="text-sm font-semibold text-white">Threat Intelligence Sources</h3>
                <p className="text-[10px] text-gray-500">Connected feeds and sync status</p>
              </div>
            </div>
            {expandedSection === 'intel' ? <ChevronUp className="h-4 w-4 text-gray-400" /> : <ChevronDown className="h-4 w-4 text-gray-400" />}
          </button>
          {expandedSection === 'intel' && (
            <div className="mt-4 pt-4 border-t border-surface-border space-y-2">
              {intelSources.map((source) => (
                <div key={source.name} className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface/50">
                  <div className="flex items-center gap-2">
                    <div className={cn(
                      'w-1.5 h-1.5 rounded-full',
                      source.status === 'connected' ? 'bg-accent-green animate-pulse' : 'bg-gray-500'
                    )} />
                    <span className="text-xs text-white">{source.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-gray-500">{source.lastSync}</span>
                    <Badge variant={source.status === 'connected' ? 'success' : 'default'} size="sm">{source.status}</Badge>
                  </div>
                </div>
              ))}
              <Button size="sm" variant="secondary" icon={<Plus className="h-3.5 w-3.5" />}>
                Add Source
              </Button>
            </div>
          )}
        </Card>

        {/* Response Automation */}
        <Card>
          <button
            onClick={() => toggleSection('automation')}
            className="w-full flex items-center justify-between"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-accent-orange/10 text-accent-orange">
                <RefreshCw className="h-4 w-4" />
              </div>
              <div className="text-left">
                <h3 className="text-sm font-semibold text-white">Response Automation Level</h3>
                <p className="text-[10px] text-gray-500">Set automated response aggressiveness</p>
              </div>
            </div>
            {expandedSection === 'automation' ? <ChevronUp className="h-4 w-4 text-gray-400" /> : <ChevronDown className="h-4 w-4 text-gray-400" />}
          </button>
          {expandedSection === 'automation' && (
            <div className="mt-4 pt-4 border-t border-surface-border space-y-3">
              {automationLevels.map((level, idx) => (
                <button
                  key={idx}
                  onClick={() => setAutomationLevel(idx)}
                  className={cn(
                    'w-full flex items-start gap-3 px-4 py-3 rounded-lg border text-left transition-colors',
                    automationLevel === idx
                      ? 'bg-accent-cyan/10 border-accent-cyan/30'
                      : 'bg-surface/50 border-surface-border hover:border-gray-600'
                  )}
                >
                  <div className={cn(
                    'w-4 h-4 rounded-full border-2 mt-0.5 flex items-center justify-center shrink-0 transition-colors',
                    automationLevel === idx ? 'border-accent-cyan' : 'border-gray-600'
                  )}>
                    {automationLevel === idx && <div className="w-2 h-2 rounded-full bg-accent-cyan" />}
                  </div>
                  <div>
                    <p className={cn('text-xs font-medium', automationLevel === idx ? 'text-accent-cyan' : 'text-white')}>{level.level}</p>
                    <p className="text-[10px] text-gray-500 mt-0.5">{level.description}</p>
                  </div>
                </button>
              ))}
            </div>
          )}
        </Card>

        {/* API Keys */}
        <Card>
          <button
            onClick={() => toggleSection('api-keys')}
            className="w-full flex items-center justify-between"
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-accent-red/10 text-accent-red">
                <Key className="h-4 w-4" />
              </div>
              <div className="text-left">
                <h3 className="text-sm font-semibold text-white">API Keys</h3>
                <p className="text-[10px] text-gray-500">Manage API access credentials</p>
              </div>
            </div>
            {expandedSection === 'api-keys' ? <ChevronUp className="h-4 w-4 text-gray-400" /> : <ChevronDown className="h-4 w-4 text-gray-400" />}
          </button>
          {expandedSection === 'api-keys' && (
            <div className="mt-4 pt-4 border-t border-surface-border space-y-3">
              {apiKeys.map((ak) => (
                <div key={ak.id} className="flex items-center gap-3 px-3 py-2.5 rounded-lg bg-surface/50">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="text-xs font-medium text-white">{ak.name}</span>
                      <Badge variant={ak.enabled ? 'success' : 'default'} size="sm">{ak.enabled ? 'Active' : 'Disabled'}</Badge>
                    </div>
                    <div className="flex items-center gap-3 mt-1">
                      <div className="flex items-center gap-1">
                        <span className="text-[10px] text-gray-500 font-mono">
                          {showKey === ak.id ? ak.key : 'sx_pk_•••••••••••'}
                        </span>
                        <button
                          onClick={() => setShowKey(showKey === ak.id ? null : ak.id)}
                          className="text-gray-500 hover:text-white transition-colors"
                        >
                          {showKey === ak.id ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                        </button>
                      </div>
                      <span className="text-[10px] text-gray-600">Created: {ak.createdAt}</span>
                      <span className="text-[10px] text-gray-600">Last used: {ak.lastUsed}</span>
                    </div>
                  </div>
                  <button className="p-1 text-gray-500 hover:text-accent-red transition-colors">
                    <Trash2 className="h-3.5 w-3.5" />
                  </button>
                </div>
              ))}
              <Button size="sm" variant="secondary" icon={<Plus className="h-3.5 w-3.5" />}>
                Generate New Key
              </Button>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
