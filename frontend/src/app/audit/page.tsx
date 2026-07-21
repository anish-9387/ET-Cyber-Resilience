'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { api, ApiError, AuditEntry } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Button } from '@/components/ui/Button';
import { Badge } from '@/components/ui/Badge';
import {
  EmptyState,
  ErrorState,
  InlineError,
  LoadingState,
} from '@/components/ui/States';
import { cn } from '@/lib/utils';
import {
  ScrollText,
  Bot,
  User,
  ChevronDown,
  ChevronUp,
  Undo2,
  Check,
  GitCompare,
  Search,
  FileText,
} from 'lucide-react';

function outcomeVariant(outcome: string): 'success' | 'danger' | 'warning' | 'default' {
  const normalized = (outcome || '').toLowerCase();
  if (['success', 'succeeded', 'completed', 'executed'].includes(normalized))
    return 'success';
  if (['failed', 'error', 'rejected'].includes(normalized)) return 'danger';
  if (['pending', 'in_progress', 'partial'].includes(normalized)) return 'warning';
  return 'default';
}

function AuditRow({ entry, onRollback }: { entry: AuditEntry; onRollback: (id: string) => void }) {
  const [open, setOpen] = useState(false);
  const isAutomated = entry.actor_type !== 'human';

  return (
    <div className="transition-colors">
      <button
        onClick={() => setOpen(!open)}
        className="w-full px-5 py-3.5 flex items-start gap-3 hover:bg-surface/30 transition-colors text-left"
      >
        <div
          className={cn(
            'p-1.5 rounded-lg shrink-0 mt-0.5',
            isAutomated
              ? 'bg-accent-blue/15 text-accent-blue'
              : 'bg-accent-green/15 text-accent-green'
          )}
        >
          {isAutomated ? <Bot className="h-3.5 w-3.5" /> : <User className="h-3.5 w-3.5" />}
        </div>

        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs font-medium text-white">{entry.action}</span>
            <span className="text-[10px] text-gray-500 font-mono">→ {entry.target}</span>
            <Badge variant={outcomeVariant(entry.outcome)} size="sm">
              {entry.outcome}
            </Badge>
            {entry.approved_by && (
              <span className="flex items-center gap-1 text-[10px] text-accent-green">
                <Check className="h-3 w-3" />
                {entry.approved_by}
              </span>
            )}
            {entry.rollback_available && (
              <Badge variant="info" size="sm">
                rollback available
              </Badge>
            )}
          </div>
          <div className="flex items-center gap-3 mt-1 flex-wrap">
            <span className="text-[10px] text-gray-600 font-mono">
              {new Date(entry.timestamp).toLocaleString()}
            </span>
            <span className="text-[10px] text-gray-600">
              by {entry.actor} ({entry.actor_type})
            </span>
            <span className="text-[10px] text-gray-600 font-mono">
              confidence {Math.round(entry.confidence * 100)}%
            </span>
          </div>
        </div>

        {open ? (
          <ChevronUp className="h-4 w-4 text-gray-500 shrink-0 mt-1" />
        ) : (
          <ChevronDown className="h-4 w-4 text-gray-500 shrink-0 mt-1" />
        )}
      </button>

      {open && (
        <div className="px-5 pb-5 pl-14 space-y-4 bg-surface/20">
          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">
              Decision
            </p>
            <p className="text-xs text-white">{entry.decision}</p>
          </div>

          <div>
            <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">
              Reasoning
            </p>
            <p className="text-xs text-gray-300">{entry.reasoning}</p>
          </div>

          {entry.evidence?.length > 0 && (
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5 flex items-center gap-1">
                <FileText className="h-3 w-3" />
                Evidence relied on
              </p>
              <ul className="space-y-1">
                {entry.evidence.map((item, idx) => (
                  <li
                    key={idx}
                    className="text-[11px] text-gray-400 flex items-start gap-1.5"
                  >
                    <span className="text-accent-blue mt-0.5">•</span>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {entry.alternatives?.length > 0 && (
            <div>
              <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5 flex items-center gap-1">
                <GitCompare className="h-3 w-3" />
                Alternatives considered and rejected
              </p>
              <ul className="space-y-1">
                {entry.alternatives.map((item, idx) => (
                  <li
                    key={idx}
                    className="text-[11px] text-gray-500 flex items-start gap-1.5"
                  >
                    <span className="text-gray-600 mt-0.5">◦</span>
                    {item}
                  </li>
                ))}
              </ul>
            </div>
          )}

          <div className="flex items-center gap-3 flex-wrap">
            <span className="text-[10px] text-gray-600 font-mono">id {entry.id}</span>
            {entry.rollback_available && (
              <Button
                size="sm"
                variant="secondary"
                onClick={() => onRollback(entry.id)}
                icon={<Undo2 className="h-3.5 w-3.5" />}
              >
                Roll back
              </Button>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

export default function AuditPage() {
  const [search, setSearch] = useState('');
  const [actorType, setActorType] = useState<'all' | 'automated' | 'human'>('all');
  const [rollbackError, setRollbackError] = useState<ApiError | null>(null);
  const [rollbackMsg, setRollbackMsg] = useState<string | null>(null);

  const state = useApi(() => api.getAuditTrail({ limit: 200 }), [], 10000);

  const entries = state.data ?? [];
  const filtered = entries.filter((entry) => {
    if (actorType === 'automated' && entry.actor_type === 'human') return false;
    if (actorType === 'human' && entry.actor_type !== 'human') return false;
    if (search) {
      const haystack =
        `${entry.action} ${entry.target} ${entry.actor} ${entry.reasoning}`.toLowerCase();
      if (!haystack.includes(search.toLowerCase())) return false;
    }
    return true;
  });

  const handleRollback = async (id: string) => {
    setRollbackError(null);
    setRollbackMsg(null);
    try {
      await api.rollbackExecution(id);
      setRollbackMsg(`Rollback requested for ${id}`);
      state.refetch();
    } catch (err) {
      setRollbackError(
        err instanceof ApiError
          ? err
          : new ApiError('Rollback failed', 0, '/decision/rollback')
      );
    }
  };

  const automatedCount = entries.filter((e) => e.actor_type !== 'human').length;
  const approvedCount = entries.filter((e) => e.approved_by).length;

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <div className="flex items-center gap-2.5">
              <ScrollText className="h-5 w-5 text-accent-blue" />
              <h1 className="text-xl font-bold text-white">Audit Trail</h1>
            </div>
            <p className="text-xs text-gray-500 mt-1">
              Every automated action with the evidence it relied on, its reasoning,
              the alternatives it rejected, who approved it, and whether it can be
              rolled back.
            </p>
          </div>

          {entries.length > 0 && (
            <div className="flex items-center gap-3 flex-wrap">
              {[
                ['Actions logged', entries.length, 'text-white'],
                ['Automated', automatedCount, 'text-accent-blue'],
                ['Human-approved', approvedCount, 'text-accent-green'],
              ].map(([label, value, color]) => (
                <div
                  key={label as string}
                  className="px-3 py-2 rounded-lg bg-surface-card border border-surface-border"
                >
                  <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                    {label as string}
                  </p>
                  <p className={cn('text-lg font-bold font-mono', color as string)}>
                    {value as number}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        {rollbackError && <InlineError error={rollbackError} />}
        {rollbackMsg && (
          <div className="px-4 py-2.5 rounded-lg bg-accent-green/10 border border-accent-green/25">
            <p className="text-xs text-accent-green">{rollbackMsg}</p>
          </div>
        )}

        <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-surface-border space-y-3">
            <div className="flex items-center justify-between gap-3 flex-wrap">
              <h3 className="text-sm font-semibold text-white">
                Action Log
                {filtered.length !== entries.length && (
                  <span className="text-[10px] text-gray-500 font-mono ml-2">
                    {filtered.length} of {entries.length}
                  </span>
                )}
              </h3>
              <p className="text-[10px] text-gray-500 font-mono">GET /audit/trail</p>
            </div>
            <div className="flex items-center gap-3 flex-wrap">
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
                <input
                  type="text"
                  placeholder="Search actions, targets, reasoning…"
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="w-full pl-8 pr-3 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-accent-blue/50"
                />
              </div>
              <div className="flex items-center gap-1.5">
                {(['all', 'automated', 'human'] as const).map((f) => (
                  <button
                    key={f}
                    onClick={() => setActorType(f)}
                    className={cn(
                      'px-2 py-1 text-[10px] rounded font-medium transition-colors capitalize',
                      actorType === f
                        ? 'bg-accent-blue/20 text-accent-blue border border-accent-blue/30'
                        : 'text-gray-500 hover:text-white hover:bg-surface-border'
                    )}
                  >
                    {f}
                  </button>
                ))}
              </div>
            </div>
          </div>

          {state.initialLoading && <LoadingState label="Loading audit trail…" />}
          {!state.initialLoading && state.error && (
            <ErrorState error={state.error} onRetry={state.refetch} />
          )}
          {!state.initialLoading && !state.error && entries.length === 0 && (
            <EmptyState
              title="No actions recorded"
              message="Nothing has been executed yet. Actions taken from the Decision page will be logged here with full provenance."
            />
          )}
          {entries.length > 0 && filtered.length === 0 && (
            <div className="px-5 py-8 text-center text-sm text-gray-500">
              No entries match the current filters
            </div>
          )}

          {filtered.length > 0 && (
            <div className="divide-y divide-surface-border">
              {filtered.map((entry) => (
                <AuditRow key={entry.id} entry={entry} onRollback={handleRollback} />
              ))}
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
