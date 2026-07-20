'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { api, ApiError, DecisionOption } from '@/lib/api';
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
  Scale,
  ShieldCheck,
  Check,
  X,
  Star,
  Undo2,
  UserCheck,
  AlertOctagon,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

/** Who the console attributes actions to. No auth is enforced by the backend. */
const OPERATOR = 'console-operator';

function pct(value: number) {
  return `${Math.round(value * 100)}%`;
}

/** Lower is better for cost/impact/blast columns; higher is better for reduction. */
function metricColor(value: number, invert = false): string {
  const v = invert ? 1 - value : value;
  if (v >= 0.66) return 'text-accent-red';
  if (v >= 0.33) return 'text-accent-yellow';
  return 'text-accent-green';
}

/* -------------------------------------------------------------------------- */
/* Pending approvals — the human-in-the-loop gate                              */
/* -------------------------------------------------------------------------- */

function ApprovalQueue({ onChanged }: { onChanged: () => void }) {
  const state = useApi(() => api.getPendingApprovals(), [], 3000);
  const [busy, setBusy] = useState<string | null>(null);
  const [actionError, setActionError] = useState<ApiError | null>(null);
  const [reasons, setReasons] = useState<Record<string, string>>({});

  const decide = async (
    executionId: string,
    decision: 'approve' | 'reject'
  ) => {
    setBusy(executionId);
    setActionError(null);
    try {
      await api.approveExecution(
        executionId,
        OPERATOR,
        decision,
        reasons[executionId] || `${decision}d from decision console`
      );
      state.refetch();
      onChanged();
    } catch (err) {
      setActionError(
        err instanceof ApiError
          ? err
          : new ApiError('Approval failed', 0, '/decision/approve')
      );
    } finally {
      setBusy(null);
    }
  };

  const pending = state.data ?? [];
  const hasPending = pending.length > 0;

  return (
    <div
      className={cn(
        'rounded-xl overflow-hidden border-2 transition-colors',
        hasPending
          ? 'border-accent-yellow/50 bg-accent-yellow/[0.03] shadow-[0_0_20px_rgba(234,179,8,0.12)]'
          : 'border-surface-border bg-surface-card'
      )}
    >
      <div className="px-5 py-4 border-b border-surface-border flex items-center gap-3">
        <div
          className={cn(
            'p-2 rounded-lg',
            hasPending
              ? 'bg-accent-yellow/20 text-accent-yellow'
              : 'bg-surface text-gray-500'
          )}
        >
          <UserCheck className="h-5 w-5" />
        </div>
        <div>
          <h2 className="text-sm font-semibold text-white">
            Human Approval Required
          </h2>
          <p className="text-[10px] text-gray-500">
            No high-impact action executes without an operator decision.
          </p>
        </div>
        {hasPending && (
          <Badge variant="warning" size="md" className="ml-auto animate-pulse">
            {pending.length} awaiting
          </Badge>
        )}
      </div>

      {state.initialLoading && <LoadingState label="Checking approval queue…" />}
      {!state.initialLoading && state.error && (
        <ErrorState error={state.error} onRetry={state.refetch} />
      )}
      {!state.initialLoading && !state.error && !hasPending && (
        <div className="px-5 py-6 flex items-center gap-3">
          <ShieldCheck className="h-5 w-5 text-accent-green shrink-0" />
          <div>
            <p className="text-xs text-gray-300">No actions awaiting approval</p>
            <p className="text-[10px] text-gray-600">
              Queued actions requiring sign-off will appear here.
            </p>
          </div>
        </div>
      )}

      {hasPending && (
        <div className="divide-y divide-surface-border">
          {actionError && (
            <div className="p-4">
              <InlineError error={actionError} />
            </div>
          )}
          {pending.map((item) => (
            <div key={item.execution_id} className="p-5 space-y-3">
              <div className="flex items-start gap-3 flex-wrap">
                <AlertOctagon className="h-4 w-4 text-accent-yellow mt-0.5 shrink-0" />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium text-white">{item.action}</p>
                  <p className="text-xs text-gray-400 mt-0.5">{item.description}</p>
                </div>
                <Badge
                  variant={item.risk_level === 'high' ? 'danger' : 'warning'}
                  size="sm"
                >
                  {item.risk_level} risk
                </Badge>
              </div>

              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {[
                  ['Attack ↓', pct(item.attack_success_reduction), 'text-accent-green'],
                  ['Mission impact', pct(item.mission_impact), 'text-accent-yellow'],
                  ['Requested by', item.requested_by, 'text-gray-300'],
                  [
                    'Requested',
                    new Date(item.requested_at).toLocaleTimeString(),
                    'text-gray-300',
                  ],
                ].map(([label, value, color]) => (
                  <div key={label} className="px-2.5 py-1.5 rounded-lg bg-surface/60">
                    <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                      {label}
                    </p>
                    <p className={cn('text-xs font-mono font-medium truncate', color)}>
                      {value}
                    </p>
                  </div>
                ))}
              </div>

              {item.rationale && (
                <p className="text-[11px] text-gray-400 px-3 py-2 rounded-lg bg-surface/60">
                  {item.rationale}
                </p>
              )}

              <input
                type="text"
                placeholder="Reason for the record (optional)…"
                value={reasons[item.execution_id] ?? ''}
                onChange={(e) =>
                  setReasons((prev) => ({
                    ...prev,
                    [item.execution_id]: e.target.value,
                  }))
                }
                className="w-full px-3 py-2 text-xs bg-surface border border-surface-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-accent-cyan/50"
              />

              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="primary"
                  loading={busy === item.execution_id}
                  onClick={() => decide(item.execution_id, 'approve')}
                  icon={<Check className="h-3.5 w-3.5" />}
                >
                  Approve
                </Button>
                <Button
                  size="sm"
                  variant="danger"
                  disabled={busy === item.execution_id}
                  onClick={() => decide(item.execution_id, 'reject')}
                  icon={<X className="h-3.5 w-3.5" />}
                >
                  Reject
                </Button>
                <span className="text-[10px] text-gray-600 font-mono ml-auto truncate">
                  {item.execution_id}
                </span>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Options comparison                                                          */
/* -------------------------------------------------------------------------- */

function OptionRow({
  option,
  recommended,
  onExecute,
  busy,
}: {
  option: DecisionOption;
  recommended: boolean;
  onExecute: (id: string) => void;
  busy: boolean;
}) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <tr
        className={cn(
          'border-b border-surface-border transition-colors',
          recommended ? 'bg-accent-green/[0.06]' : 'hover:bg-surface/30'
        )}
      >
        <td className="px-4 py-3">
          <div className="flex items-start gap-2">
            {recommended && (
              <Star className="h-3.5 w-3.5 text-accent-green fill-accent-green shrink-0 mt-0.5" />
            )}
            <div className="min-w-0">
              <p className="text-xs font-medium text-white">{option.action}</p>
              <p className="text-[10px] text-gray-500 mt-0.5 line-clamp-2">
                {option.description}
              </p>
              <div className="flex items-center gap-1.5 mt-1 flex-wrap">
                {recommended && (
                  <Badge variant="success" size="sm">
                    Recommended
                  </Badge>
                )}
                {option.approval_required && (
                  <Badge variant="warning" size="sm">
                    Needs approval
                  </Badge>
                )}
                {option.reversible && (
                  <Badge variant="info" size="sm">
                    Reversible
                  </Badge>
                )}
              </div>
            </div>
          </div>
        </td>
        <td className="px-4 py-3 text-center">
          <span className="text-sm font-mono font-bold text-accent-green">
            −{pct(option.attack_success_reduction)}
          </span>
          <p className="text-[9px] text-gray-600 font-mono">
            to {pct(option.attack_success_after)}
          </p>
        </td>
        <td className="px-4 py-3 text-center">
          <span
            className={cn('text-sm font-mono font-bold', metricColor(option.mission_impact))}
          >
            {pct(option.mission_impact)}
          </span>
        </td>
        <td className="px-4 py-3 text-center">
          <span
            className={cn('text-sm font-mono font-bold', metricColor(option.recovery_cost))}
          >
            {pct(option.recovery_cost)}
          </span>
        </td>
        <td className="px-4 py-3 text-center">
          <span
            className={cn('text-sm font-mono font-bold', metricColor(option.blast_radius))}
          >
            {pct(option.blast_radius)}
          </span>
        </td>
        <td className="px-4 py-3 text-center">
          <Badge
            variant={
              option.risk_level === 'high'
                ? 'danger'
                : option.risk_level === 'medium'
                  ? 'warning'
                  : 'success'
            }
            size="sm"
          >
            {option.risk_level}
          </Badge>
        </td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-1.5 justify-end">
            <Button
              size="sm"
              variant={recommended ? 'primary' : 'secondary'}
              loading={busy}
              onClick={() => onExecute(option.id)}
            >
              Execute
            </Button>
            <button
              onClick={() => setOpen(!open)}
              className="p-1 text-gray-500 hover:text-white transition-colors"
            >
              {open ? (
                <ChevronUp className="h-4 w-4" />
              ) : (
                <ChevronDown className="h-4 w-4" />
              )}
            </button>
          </div>
        </td>
      </tr>

      {open && (
        <tr className="border-b border-surface-border bg-surface/40">
          <td colSpan={7} className="px-6 py-4">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
              <div className="lg:col-span-2">
                <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">
                  Rationale
                </p>
                <p className="text-xs text-gray-300">{option.rationale}</p>
                {option.evidence?.length > 0 && (
                  <>
                    <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1 mt-3">
                      Supporting evidence
                    </p>
                    <ul className="space-y-1">
                      {option.evidence.map((item, idx) => (
                        <li
                          key={idx}
                          className="text-[11px] text-gray-400 flex items-start gap-1.5"
                        >
                          <span className="text-accent-cyan mt-0.5">•</span>
                          {item}
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </div>
              <div className="space-y-2">
                <div className="px-3 py-2 rounded-lg bg-surface/60">
                  <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                    Score
                  </p>
                  <p className="text-sm font-mono font-bold text-accent-cyan">
                    {option.score.toFixed(3)}
                  </p>
                </div>
                <div className="px-3 py-2 rounded-lg bg-surface/60">
                  <p className="text-[9px] text-gray-500 uppercase tracking-wider flex items-center gap-1">
                    <Undo2 className="h-3 w-3" />
                    Rollback
                  </p>
                  <p className="text-[11px] text-gray-300">
                    {option.rollback || 'Not specified'}
                  </p>
                </div>
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  );
}

/* -------------------------------------------------------------------------- */

export default function DecisionPage() {
  const state = useApi(() => api.getDecisionOptions(), [], 5000);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [execError, setExecError] = useState<ApiError | null>(null);
  const [lastResult, setLastResult] = useState<string | null>(null);
  const [approvalNonce, setApprovalNonce] = useState(0);

  const execute = async (optionId: string) => {
    setBusyId(optionId);
    setExecError(null);
    setLastResult(null);
    try {
      const result = await api.executeDecision(optionId, OPERATOR);
      setLastResult(
        result.status === 'pending_approval'
          ? `Queued for approval — execution ${result.execution_id}`
          : `Executed — ${result.steps?.length ?? 0} steps, audit ${result.audit_id}`
      );
      setApprovalNonce((n) => n + 1);
      state.refetch();
    } catch (err) {
      setExecError(
        err instanceof ApiError
          ? err
          : new ApiError('Execution failed', 0, '/decision/execute')
      );
    } finally {
      setBusyId(null);
    }
  };

  const options = state.data?.options ?? [];
  const recommendedId = state.data?.recommended_id;
  const sorted = options
    .slice()
    .sort((a, b) =>
      a.id === recommendedId ? -1 : b.id === recommendedId ? 1 : b.score - a.score
    );

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <div className="flex items-center gap-2.5">
            <Scale className="h-5 w-5 text-accent-cyan" />
            <h1 className="text-xl font-bold text-white">Decision Engine</h1>
          </div>
          <p className="text-xs text-gray-500 mt-1">
            Response options ranked by expected attack-success reduction against
            mission cost. Every option carries its reasoning and a rollback path.
          </p>
        </div>

        {/* Approval gate first — it is the most consequential control here. */}
        <ApprovalQueue key={approvalNonce} onChanged={() => state.refetch()} />

        {execError && <InlineError error={execError} />}
        {lastResult && (
          <div className="px-4 py-2.5 rounded-lg bg-accent-green/10 border border-accent-green/25">
            <p className="text-xs text-accent-green">{lastResult}</p>
          </div>
        )}

        <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-surface-border">
            <h3 className="text-sm font-semibold text-white">Response Options</h3>
            <p className="text-[10px] text-gray-500 font-mono">
              GET /decision/options
            </p>
          </div>

          {state.initialLoading && <LoadingState label="Scoring options…" />}
          {!state.initialLoading && state.error && (
            <ErrorState error={state.error} onRetry={state.refetch} />
          )}
          {!state.initialLoading && !state.error && sorted.length === 0 && (
            <EmptyState
              title="No response options"
              message="The decision engine has nothing to act on — there is no active threat in the world model."
            />
          )}

          {sorted.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-surface-border bg-surface/50">
                    {[
                      ['Action', 'text-left'],
                      ['Attack success ↓', 'text-center'],
                      ['Mission impact', 'text-center'],
                      ['Recovery cost', 'text-center'],
                      ['Blast radius', 'text-center'],
                      ['Risk', 'text-center'],
                      ['', 'text-right'],
                    ].map(([label, align]) => (
                      <th
                        key={label}
                        className={cn(
                          'px-4 py-3 font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap',
                          align
                        )}
                      >
                        {label}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {sorted.map((option) => (
                    <OptionRow
                      key={option.id}
                      option={option}
                      recommended={option.id === recommendedId}
                      onExecute={execute}
                      busy={busyId === option.id}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </DashboardLayout>
  );
}
