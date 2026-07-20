'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { api, API_BASE, Agent, ApiError } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Card } from '@/components/ui/Card';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import {
  EmptyState,
  ErrorState,
  InlineError,
  LoadingState,
} from '@/components/ui/States';
import {
  Sliders,
  Shield,
  Server,
  ChevronDown,
  ChevronUp,
  ToggleLeft,
  ToggleRight,
  Info,
  Plug,
} from 'lucide-react';

function Section({
  id,
  title,
  subtitle,
  icon,
  iconClass,
  expanded,
  onToggle,
  children,
}: {
  id: string;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  iconClass: string;
  expanded: boolean;
  onToggle: (id: string) => void;
  children: React.ReactNode;
}) {
  return (
    <Card>
      <button
        onClick={() => onToggle(id)}
        className="w-full flex items-center justify-between"
      >
        <div className="flex items-center gap-3">
          <div className={cn('p-2 rounded-lg', iconClass)}>{icon}</div>
          <div className="text-left">
            <h3 className="text-sm font-semibold text-white">{title}</h3>
            <p className="text-[10px] text-gray-500">{subtitle}</p>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="h-4 w-4 text-gray-400" />
        ) : (
          <ChevronDown className="h-4 w-4 text-gray-400" />
        )}
      </button>
      {expanded && (
        <div className="mt-4 pt-4 border-t border-surface-border">{children}</div>
      )}
    </Card>
  );
}

/**
 * Settings.
 *
 * The API exposes no settings, webhook or API-key endpoints, so the notification
 * channels, API keys and threat-feed lists that this panel used to render (all
 * hardcoded) have been removed rather than re-faked. What remains is real: the
 * backend connection, live service health, and agent enable/disable, which is a
 * genuine PUT /agents/{id}.
 */
export function SettingsPanel() {
  const [expanded, setExpanded] = useState<string | null>('connection');
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);

  // Display-only preferences. Not persisted anywhere — labelled as such.
  const [refreshInterval, setRefreshInterval] = useState('5');

  const health = useApi(() => api.getHealth(), [], 15000);
  const agents = useApi(() => api.getAgents(), [], 10000);

  const toggle = (id: string) => setExpanded(expanded === id ? null : id);

  const toggleAgent = async (agent: Agent) => {
    setBusy(agent.id);
    setActionError(null);
    try {
      await api.updateAgent(agent.id, {
        status: agent.status === 'disabled' ? 'idle' : 'disabled',
      });
      agents.refetch();
    } catch (err) {
      setActionError(
        err instanceof ApiError ? err : new ApiError('Update failed', 0, '/agents')
      );
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-6 max-w-4xl">
      <div>
        <h2 className="text-xl font-bold text-white">Settings</h2>
        <p className="text-xs text-gray-500 mt-1">Platform configuration and status</p>
      </div>

      {actionError && <InlineError error={actionError} />}

      <div className="space-y-3">
        {/* Backend connection */}
        <Section
          id="connection"
          title="Backend Connection"
          subtitle="API endpoint and service health"
          icon={<Plug className="h-4 w-4" />}
          iconClass="bg-accent-cyan/10 text-accent-cyan"
          expanded={expanded === 'connection'}
          onToggle={toggle}
        >
          <div className="space-y-4">
            <div>
              <label className="text-xs text-gray-400 block mb-1">API base URL</label>
              <p className="px-3 py-2 text-xs bg-surface border border-surface-border rounded-lg text-accent-cyan font-mono break-all">
                {API_BASE}
              </p>
              <p className="text-[10px] text-gray-600 mt-1">
                Set via <span className="font-mono">NEXT_PUBLIC_API_URL</span> at build
                time.
              </p>
            </div>

            <div>
              <p className="text-xs text-gray-400 mb-2">Service health</p>
              {health.initialLoading && <LoadingState label="Checking services…" />}
              {!health.initialLoading && health.error && (
                <ErrorState error={health.error} onRetry={health.refetch} />
              )}
              {health.data && !health.error && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2 px-3 py-2 rounded-lg bg-surface/50">
                    <span className="text-xs text-white font-medium">
                      {health.data.name}
                    </span>
                    <span className="text-[10px] text-gray-500 font-mono">
                      v{health.data.version}
                    </span>
                    <Badge
                      variant={health.data.status === 'healthy' ? 'success' : 'warning'}
                      size="sm"
                      className="ml-auto"
                    >
                      {health.data.status}
                    </Badge>
                  </div>
                  {Object.entries(health.data.services ?? {}).map(([name, service]) => (
                    <div
                      key={name}
                      className="flex items-center justify-between px-3 py-2 rounded-lg bg-surface/50"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className={cn(
                            'w-1.5 h-1.5 rounded-full shrink-0',
                            service.status === 'healthy'
                              ? 'bg-accent-green animate-pulse'
                              : service.status === 'unhealthy'
                                ? 'bg-accent-red'
                                : 'bg-gray-500'
                          )}
                        />
                        <span className="text-xs text-white capitalize">{name}</span>
                        {service.error && (
                          <span className="text-[10px] text-gray-600 font-mono truncate">
                            {service.error}
                          </span>
                        )}
                      </div>
                      <Badge
                        variant={
                          service.status === 'healthy'
                            ? 'success'
                            : service.status === 'unhealthy'
                              ? 'danger'
                              : 'default'
                        }
                        size="sm"
                      >
                        {service.status}
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </Section>

        {/* Display preferences */}
        <Section
          id="general"
          title="Display Preferences"
          subtitle="Local-only view options"
          icon={<Sliders className="h-4 w-4" />}
          iconClass="bg-accent-yellow/10 text-accent-yellow"
          expanded={expanded === 'general'}
          onToggle={toggle}
        >
          <div className="space-y-4">
            <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-accent-cyan/5 border border-accent-cyan/20">
              <Info className="h-3.5 w-3.5 text-accent-cyan shrink-0 mt-0.5" />
              <p className="text-[11px] text-gray-400">
                The API has no settings endpoint, so these preferences are not
                persisted — they reset on reload.
              </p>
            </div>
            <div className="max-w-xs">
              <label className="text-xs text-gray-400 block mb-1">
                Live page refresh interval
              </label>
              <select
                value={refreshInterval}
                onChange={(e) => setRefreshInterval(e.target.value)}
                className="w-full px-3 py-2 text-xs bg-surface border border-surface-border rounded-lg text-gray-300 focus:outline-none focus:border-accent-cyan/50"
              >
                <option value="2">2 seconds</option>
                <option value="5">5 seconds</option>
                <option value="10">10 seconds</option>
                <option value="30">30 seconds</option>
              </select>
            </div>
          </div>
        </Section>

        {/* Agents */}
        <Section
          id="agents"
          title="Agent Configuration"
          subtitle="Enable or disable registered agents"
          icon={<Shield className="h-4 w-4" />}
          iconClass="bg-accent-green/10 text-accent-green"
          expanded={expanded === 'agents'}
          onToggle={toggle}
        >
          {agents.initialLoading && <LoadingState label="Loading agents…" />}
          {!agents.initialLoading && agents.error && (
            <ErrorState error={agents.error} onRetry={agents.refetch} />
          )}
          {!agents.initialLoading && !agents.error && (agents.data?.length ?? 0) === 0 && (
            <EmptyState
              title="No agents registered"
              message="Register agents to configure them here."
              className="py-8"
            />
          )}
          {(agents.data?.length ?? 0) > 0 && (
            <div className="space-y-2">
              {agents.data!.map((agent) => {
                const disabled = agent.status === 'disabled';
                return (
                  <div
                    key={agent.id}
                    className="flex items-center justify-between px-3 py-2.5 rounded-lg bg-surface/50 gap-3"
                  >
                    <div className="min-w-0">
                      <p className="text-xs font-medium text-white truncate">
                        {agent.name}
                      </p>
                      <p className="text-[10px] text-gray-500">
                        {agent.agent_type.replace(/_/g, ' ')} · {agent.status}
                      </p>
                    </div>
                    <button
                      onClick={() => toggleAgent(agent)}
                      disabled={busy === agent.id}
                      className={cn(
                        'p-1 rounded transition-colors shrink-0 disabled:opacity-50',
                        !disabled
                          ? 'text-accent-green hover:text-accent-green/80'
                          : 'text-gray-600 hover:text-gray-400'
                      )}
                    >
                      {!disabled ? (
                        <ToggleRight className="h-5 w-5" />
                      ) : (
                        <ToggleLeft className="h-5 w-5" />
                      )}
                    </button>
                  </div>
                );
              })}
            </div>
          )}
        </Section>

        {/* Not available */}
        <Section
          id="unavailable"
          title="Notifications, API Keys &amp; Feeds"
          subtitle="Not exposed by the current API"
          icon={<Server className="h-4 w-4" />}
          iconClass="bg-gray-500/10 text-gray-400"
          expanded={expanded === 'unavailable'}
          onToggle={toggle}
        >
          <div className="flex items-start gap-2 px-3 py-2.5 rounded-lg bg-surface/50">
            <Info className="h-3.5 w-3.5 text-gray-500 shrink-0 mt-0.5" />
            <div className="space-y-1">
              <p className="text-[11px] text-gray-400">
                Webhook channels, API key management and threat-feed configuration
                have no corresponding endpoints in the API contract, so they are not
                rendered here.
              </p>
              <p className="text-[11px] text-gray-600">
                They will appear once the backend exposes them.
              </p>
            </div>
          </div>
        </Section>
      </div>
    </div>
  );
}
