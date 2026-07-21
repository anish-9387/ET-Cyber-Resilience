'use client';

import { useState } from 'react';
import { cn } from '@/lib/utils';
import { api, Criticality } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { Button } from '@/components/ui/Button';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { Search, ArrowUpDown, ChevronLeft, ChevronRight } from 'lucide-react';

const statusColors: Record<string, string> = {
  new: 'text-yellow-500 bg-yellow-500/10 border-yellow-500/30',
  investigating: 'text-cyan-500 bg-cyan-500/10 border-cyan-500/30',
  contained: 'text-orange-500 bg-orange-500/10 border-orange-500/30',
  remediated: 'text-blue-400 bg-blue-500/10 border-blue-500/30',
  resolved: 'text-green-500 bg-green-500/10 border-green-500/30',
  closed: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
  false_positive: 'text-gray-500 bg-gray-500/10 border-gray-500/30',
};

type SortKey = 'id' | 'severity' | 'status' | 'created_at';

const severityOrder: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
};
const statusOrder: Record<string, number> = {
  new: 0,
  investigating: 1,
  contained: 2,
  remediated: 3,
  resolved: 4,
  closed: 5,
  false_positive: 6,
};

export function IncidentList({
  onSelect,
  selectedId,
}: {
  onSelect?: (id: string) => void;
  selectedId?: string | null;
}) {
  const [search, setSearch] = useState('');
  const [filterSeverity, setFilterSeverity] = useState<string>('all');
  const [filterStatus, setFilterStatus] = useState<string>('all');
  const [sortKey, setSortKey] = useState<SortKey>('created_at');
  const [sortAsc, setSortAsc] = useState(false);
  const [page, setPage] = useState(0);
  const perPage = 10;

  const state = useApi(
    () =>
      api.getIncidents({
        severity: filterSeverity === 'all' ? undefined : filterSeverity,
        status: filterStatus === 'all' ? undefined : filterStatus,
        search: search || undefined,
        page_size: 200,
      }),
    [filterSeverity, filterStatus, search],
    15000
  );

  const incidents = state.data ?? [];

  const sorted = incidents.slice().sort((a, b) => {
    let cmp = 0;
    if (sortKey === 'severity')
      cmp = (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9);
    else if (sortKey === 'status')
      cmp = (statusOrder[a.status] ?? 9) - (statusOrder[b.status] ?? 9);
    else if (sortKey === 'created_at')
      cmp = new Date(b.created_at).getTime() - new Date(a.created_at).getTime();
    else cmp = a.id.localeCompare(b.id);
    return sortAsc ? cmp : -cmp;
  });

  const totalPages = Math.ceil(sorted.length / perPage);
  const paginated = sorted.slice(page * perPage, (page + 1) * perPage);

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b border-surface-border space-y-3">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <h3 className="text-sm font-semibold text-white">
            Incidents
            {!state.initialLoading && !state.error && (
              <span className="text-[10px] text-gray-500 font-mono ml-2">
                {incidents.length} total
              </span>
            )}
          </h3>
          <p className="text-[10px] text-gray-500 font-mono">GET /incidents</p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
            <input
              type="text"
              placeholder="Search incidents…"
              value={search}
              onChange={(e) => {
                setSearch(e.target.value);
                setPage(0);
              }}
              className="w-full pl-8 pr-3 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-accent-blue/50"
            />
          </div>
          <select
            value={filterSeverity}
            onChange={(e) => {
              setFilterSeverity(e.target.value);
              setPage(0);
            }}
            className="px-2 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-gray-300 focus:outline-none focus:border-accent-blue/50"
          >
            <option value="all">All Severities</option>
            {['critical', 'high', 'medium', 'low'].map((s) => (
              <option key={s} value={s}>
                {s[0].toUpperCase() + s.slice(1)}
              </option>
            ))}
          </select>
          <select
            value={filterStatus}
            onChange={(e) => {
              setFilterStatus(e.target.value);
              setPage(0);
            }}
            className="px-2 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-gray-300 focus:outline-none focus:border-accent-blue/50"
          >
            <option value="all">All Statuses</option>
            {Object.keys(statusOrder).map((s) => (
              <option key={s} value={s}>
                {s.replace(/_/g, ' ')}
              </option>
            ))}
          </select>
        </div>
      </div>

      {state.initialLoading && <LoadingState label="Loading incidents…" />}
      {!state.initialLoading && state.error && (
        <ErrorState error={state.error} onRetry={state.refetch} />
      )}
      {!state.initialLoading && !state.error && incidents.length === 0 && (
        <EmptyState
          title="No incidents"
          message="No incidents have been raised. They will appear here as detections escalate."
        />
      )}

      {paginated.length > 0 && (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-surface-border bg-surface/50">
                  {[
                    { key: 'id' as const, label: 'ID' },
                    { key: null, label: 'Title' },
                    { key: 'severity' as const, label: 'Severity' },
                    { key: 'status' as const, label: 'Status' },
                    { key: null, label: 'Type' },
                    { key: 'created_at' as const, label: 'Created' },
                    { key: null, label: 'Assigned' },
                  ].map((col) => (
                    <th
                      key={col.label}
                      className={cn(
                        'px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap',
                        col.key && 'cursor-pointer hover:text-white'
                      )}
                      onClick={() => {
                        if (!col.key) return;
                        if (sortKey === col.key) setSortAsc(!sortAsc);
                        else {
                          setSortKey(col.key);
                          setSortAsc(true);
                        }
                      }}
                    >
                      <div className="flex items-center gap-1">
                        {col.label}
                        {sortKey === col.key && <ArrowUpDown className="h-3 w-3" />}
                      </div>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {paginated.map((inc) => (
                  <tr
                    key={inc.id}
                    onClick={() => onSelect?.(inc.id)}
                    className={cn(
                      'border-b border-surface-border transition-colors',
                      onSelect && 'cursor-pointer hover:bg-surface/30',
                      selectedId === inc.id && 'bg-accent-blue/5'
                    )}
                  >
                    <td className="px-4 py-3 font-mono text-accent-blue whitespace-nowrap">
                      {inc.id.slice(0, 8)}
                    </td>
                    <td className="px-4 py-3 font-medium text-white">{inc.title}</td>
                    <td className="px-4 py-3">
                      <SeverityBadge severity={inc.severity as Criticality} />
                    </td>
                    <td className="px-4 py-3">
                      <span
                        className={cn(
                          'px-2 py-0.5 rounded text-[10px] font-medium border whitespace-nowrap',
                          statusColors[inc.status] || statusColors.new
                        )}
                      >
                        {inc.status.replace(/_/g, ' ')}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                      {inc.incident_type.replace(/_/g, ' ')}
                    </td>
                    <td className="px-4 py-3 text-gray-500 font-mono whitespace-nowrap">
                      {new Date(inc.created_at).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-gray-400">
                      {inc.assigned_to || '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {totalPages > 1 && (
            <div className="px-5 py-3 border-t border-surface-border flex items-center justify-between">
              <span className="text-[10px] text-gray-500">
                Showing {page * perPage + 1}–
                {Math.min((page + 1) * perPage, sorted.length)} of {sorted.length}
              </span>
              <div className="flex items-center gap-1">
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={page === 0}
                  onClick={() => setPage(page - 1)}
                >
                  <ChevronLeft className="h-3.5 w-3.5" />
                </Button>
                <span className="text-[10px] text-gray-400 font-mono px-2">
                  {page + 1} / {totalPages}
                </span>
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={page >= totalPages - 1}
                  onClick={() => setPage(page + 1)}
                >
                  <ChevronRight className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
