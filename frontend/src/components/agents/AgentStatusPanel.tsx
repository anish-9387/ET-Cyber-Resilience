'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { api, Agent, ApiError } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { StatusIndicator } from '@/components/ui/StatusIndicator';
import {
  EmptyState,
  ErrorState,
  InlineError,
  LoadingState,
} from '@/components/ui/States';
import {
  Bot,
  ToggleLeft,
  ToggleRight,
  ChevronDown,
  ChevronUp,
  Play,
  Clock,
} from 'lucide-react';

function statusVariant(status: Agent['status']) {
  if (status === 'running') return 'success' as const;
  if (status === 'error') return 'danger' as const;
  if (status === 'disabled') return 'default' as const;
  return 'info' as const;
}

function indicatorStatus(status: Agent['status']) {
  if (status === 'running') return 'active' as const;
  if (status === 'error') return 'error' as const;
  return 'idle' as const;
}

function heartbeatLabel(iso: string | null): string {
  if (!iso) return 'never';
  const seconds = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (Number.isNaN(seconds)) return iso;
  if (seconds < 60) return `${Math.max(seconds, 0)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

/**
 * Live agent registry from GET /agents.
 *
 * The backend exposes no per-agent run/success/failure counters, so none are
 * shown — the previous version displayed invented totals and success rates.
 */
export function AgentStatusPanel() {
  const state = useApi(() => api.getAgents(), [], 5000);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const [results, setResults] = useState<Record<string, string>>({});

  const agents = state.data ?? [];

  const toggleEnabled = async (agent: Agent) => {
    setBusy(agent.id);
    setActionError(null);
    try {
      await api.updateAgent(agent.id, {
        status: agent.status === 'disabled' ? 'idle' : 'disabled',
      });
      state.refetch();
    } catch (err) {
      setActionError(
        err instanceof ApiError ? err : new ApiError('Update failed', 0, '/agents')
      );
    } finally {
      setBusy(null);
    }
  };

  const runAgent = async (agent: Agent) => {
    setBusy(agent.id);
    setActionError(null);
    try {
      const result = await api.runAgentAction(agent.id, 'run');
      setResults((prev) => ({
        ...prev,
        [agent.id]:
          result.status === 'failed'
            ? `failed: ${result.error ?? 'unknown error'}`
            : `${result.status}${
                result.execution_time_ms !== null
                  ? ` in ${result.execution_time_ms}ms`
                  : ''
              }`,
      }));
      state.refetch();
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? err
          : new ApiError('Action failed', 0, '/agents/action')
      );
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-white">AI Agents</h3>
        {agents.length > 0 && (
          <div className="flex items-center gap-2">
            <StatusIndicator status="active" size="sm" showLabel={false} />
            <span className="text-[10px] text-gray-500">
              {agents.filter((a) => a.status === 'running').length} running ·{' '}
              {agents.length} registered
            </span>
          </div>
        )}
      </div>

      {actionError && <InlineError error={actionError} />}

      {state.initialLoading && <LoadingState label="Loading agents…" />}
      {!state.initialLoading && state.error && (
        <div className="bg-surface-card border border-surface-border rounded-xl">
          <ErrorState error={state.error} onRetry={state.refetch} />
        </div>
      )}
      {!state.initialLoading && !state.error && agents.length === 0 && (
        <div className="bg-surface-card border border-surface-border rounded-xl">
          <EmptyState
            title="No agents registered"
            message="Register an agent via POST /agents/register and it will appear here."
            icon={<Bot className="h-6 w-6" />}
          />
        </div>
      )}

      {agents.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          {agents.map((agent) => {
            const disabled = agent.status === 'disabled';
            return (
              <Card
                key={agent.id}
                className={cn(
                  'transition-all duration-200',
                  disabled && 'opacity-60',
                  agent.status === 'running' && 'border-accent-green/20',
                  agent.status === 'error' && 'border-accent-red/30'
                )}
              >
                <div className="flex items-start gap-3">
                  <div
                    className={cn(
                      'p-2 rounded-lg shrink-0',
                      agent.status === 'running'
                        ? 'bg-accent-green/10 text-accent-green'
                        : agent.status === 'error'
                          ? 'bg-accent-red/10 text-accent-red'
                          : 'bg-gray-500/10 text-gray-400'
                    )}
                  >
                    <Bot className="h-5 w-5" />
                  </div>

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <h4 className="text-sm font-semibold text-white truncate">
                        {agent.name}
                      </h4>
                      <Badge variant={statusVariant(agent.status)} size="sm">
                        {agent.status}
                      </Badge>
                    </div>
                    <p className="text-[10px] text-gray-500 mt-0.5">
                      {agent.agent_type.replace(/_/g, ' ')}
                    </p>
                    <p className="flex items-center gap-1 text-[10px] text-gray-600 mt-1 font-mono">
                      <Clock className="h-2.5 w-2.5" />
                      heartbeat {heartbeatLabel(agent.last_heartbeat)}
                    </p>
                    {results[agent.id] && (
                      <p className="text-[10px] text-accent-cyan font-mono mt-1">
                        {results[agent.id]}
                      </p>
                    )}
                  </div>

                  <div className="flex flex-col items-center gap-1 shrink-0">
                    <button
                      onClick={() => toggleEnabled(agent)}
                      disabled={busy === agent.id}
                      title={disabled ? 'Enable agent' : 'Disable agent'}
                      className={cn(
                        'p-1 rounded transition-colors disabled:opacity-50',
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
                    <button
                      onClick={() =>
                        setExpanded(expanded === agent.id ? null : agent.id)
                      }
                      className="p-1 text-gray-500 hover:text-white transition-colors"
                    >
                      {expanded === agent.id ? (
                        <ChevronUp className="h-4 w-4" />
                      ) : (
                        <ChevronDown className="h-4 w-4" />
                      )}
                    </button>
                  </div>
                </div>

                {expanded === agent.id && (
                  <div className="mt-3 pt-3 border-t border-surface-border space-y-3">
                    {agent.description && (
                      <p className="text-[11px] text-gray-400">{agent.description}</p>
                    )}
                    <div className="grid grid-cols-2 gap-2">
                      <div className="px-2.5 py-1.5 rounded bg-surface/60">
                        <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                          Registered
                        </p>
                        <p className="text-[10px] text-gray-300 font-mono">
                          {new Date(agent.created_at).toLocaleDateString()}
                        </p>
                      </div>
                      <div className="px-2.5 py-1.5 rounded bg-surface/60">
                        <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                          Updated
                        </p>
                        <p className="text-[10px] text-gray-300 font-mono">
                          {new Date(agent.updated_at).toLocaleDateString()}
                        </p>
                      </div>
                    </div>
                    {agent.tags?.length > 0 && (
                      <div className="flex flex-wrap gap-1">
                        {agent.tags.map((tag) => (
                          <Badge key={tag} variant="default" size="sm">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    )}
                    {Object.keys(agent.config ?? {}).length > 0 && (
                      <div>
                        <p className="text-[9px] text-gray-500 uppercase tracking-wider mb-1">
                          Config
                        </p>
                        <pre className="text-[10px] text-gray-400 font-mono bg-surface/60 rounded p-2 overflow-x-auto">
                          {JSON.stringify(agent.config, null, 2)}
                        </pre>
                      </div>
                    )}
                    <Button
                      size="sm"
                      variant="secondary"
                      loading={busy === agent.id}
                      onClick={() => runAgent(agent)}
                      icon={<Play className="h-3.5 w-3.5" />}
                      className="w-full"
                    >
                      Dispatch run action
                    </Button>
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </div>
  );
}
