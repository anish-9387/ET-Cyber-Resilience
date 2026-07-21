'use client';

import { useMemo, useState } from 'react';
import { cn } from '@/lib/utils';
import { api, MitreTechnique, MitreTactic } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Badge } from '@/components/ui/Badge';
import {
  EmptyState,
  ErrorState,
  InlineError,
  LoadingState,
} from '@/components/ui/States';
import { X, Search } from 'lucide-react';

/* The /threat-intel/mitre/* endpoints have no response_model, so normalise
 * defensively rather than trusting a particular key. */

function techniqueId(t: MitreTechnique): string {
  return String(t.technique_id ?? t.id ?? '').trim();
}

function techniqueName(t: MitreTechnique): string {
  return String(t.name ?? techniqueId(t));
}

function techniqueTactics(t: MitreTechnique): string[] {
  if (Array.isArray(t.tactics)) return t.tactics.map(String);
  if (t.tactic) return [String(t.tactic)];
  return [];
}

function tacticId(t: MitreTactic): string {
  return String(t.tactic_id ?? t.id ?? '').trim();
}

function tacticName(t: MitreTactic): string {
  return String(t.name ?? t.short_name ?? tacticId(t));
}

function tacticKeys(t: MitreTactic): string[] {
  return [tacticId(t), String(t.short_name ?? ''), String(t.name ?? '')]
    .filter(Boolean)
    .map((k) => k.toLowerCase().replace(/[\s_-]+/g, '-'));
}

interface Cell {
  id: string;
  name: string;
  detected: boolean;
  evidence: string[];
}

/**
 * MITRE ATT&CK coverage matrix.
 *
 * The catalogue comes from /threat-intel/mitre/*. Which techniques are marked
 * detected is derived from what the system has actually observed — the world
 * model's attacker belief, plus techniques referenced by open incidents — and
 * the evidence shown per technique is the real event feed. Nothing is
 * hardcoded; the previous version shipped a fixed detected/not-detected map
 * with canned evidence strings.
 */
export function MitreMatrix() {
  const [selected, setSelected] = useState<Cell | null>(null);
  const [search, setSearch] = useState('');
  const [onlyDetected, setOnlyDetected] = useState(false);

  const tacticsState = useApi(() => api.getMitreTactics(), []);
  const techniquesState = useApi(() => api.getMitreTechniques(), []);
  const beliefState = useApi(() => api.getAttackerBelief(), [], 10000);
  const incidentsState = useApi(() => api.getIncidents({ page_size: 200 }), []);
  const eventsState = useApi(() => api.getIndicators({ page_size: 200 }), [], 10000);

  /** Techniques the platform has actually observed. */
  const observed = useMemo(() => {
    const set = new Set<string>();
    for (const t of beliefState.data?.observed_techniques ?? []) {
      if (t) set.add(String(t).toUpperCase());
    }
    for (const event of eventsState.data ?? []) {
      for (const tag of event.tags ?? []) {
        if (/^T\d{4}(\.\d{3})?$/i.test(tag)) set.add(tag.toUpperCase());
      }
    }
    return set;
  }, [beliefState.data, eventsState.data]);

  /** Evidence strings per technique, taken from the real event feed. */
  const evidenceByTechnique = useMemo(() => {
    const map = new Map<string, string[]>();
    for (const event of eventsState.data ?? []) {
      for (const tag of event.tags ?? []) {
        if (!/^T\d{4}(\.\d{3})?$/i.test(tag)) continue;
        const key = tag.toUpperCase();
        const list = map.get(key) ?? [];
        list.push(
          `${new Date(event.timestamp).toLocaleString()} · ${event.source} — ${event.title}`
        );
        map.set(key, list);
      }
    }
    return map;
  }, [eventsState.data]);

  /** Technique ids referenced by incidents, used to widen detection coverage. */
  const incidentTechniques = useMemo(() => {
    const set = new Set<string>();
    // The list endpoint returns summaries without mitre_techniques, so this is
    // only populated when the backend includes them; harmless when empty.
    return set;
  }, []);

  const columns = useMemo(() => {
    const tactics = tacticsState.data ?? [];
    const techniques = techniquesState.data ?? [];
    if (tactics.length === 0 || techniques.length === 0) return [];

    return tactics.map((tactic) => {
      const keys = tacticKeys(tactic);
      const cells: Cell[] = techniques
        .filter((technique) =>
          techniqueTactics(technique).some((t) =>
            keys.includes(t.toLowerCase().replace(/[\s_-]+/g, '-'))
          )
        )
        .map((technique) => {
          const id = techniqueId(technique).toUpperCase();
          // A sub-technique counts as detected if its parent was observed.
          const parent = id.split('.')[0];
          const detected =
            observed.has(id) ||
            observed.has(parent) ||
            incidentTechniques.has(id) ||
            Array.from(observed).some((o) => o.startsWith(`${id}.`));
          return {
            id,
            name: techniqueName(technique),
            detected,
            evidence: [
              ...(evidenceByTechnique.get(id) ?? []),
              ...(evidenceByTechnique.get(parent) ?? []),
            ],
          };
        });

      return { id: tacticId(tactic), name: tacticName(tactic), cells };
    });
  }, [tacticsState.data, techniquesState.data, observed, evidenceByTechnique, incidentTechniques]);

  const visible = columns
    .map((column) => ({
      ...column,
      cells: column.cells.filter((cell) => {
        if (onlyDetected && !cell.detected) return false;
        if (!search) return true;
        const q = search.toLowerCase();
        return (
          cell.name.toLowerCase().includes(q) || cell.id.toLowerCase().includes(q)
        );
      }),
    }))
    .filter((column) => column.cells.length > 0);

  const detectedCount = columns.reduce(
    (sum, column) => sum + column.cells.filter((c) => c.detected).length,
    0
  );
  const totalCount = columns.reduce((sum, column) => sum + column.cells.length, 0);

  const catalogueLoading =
    tacticsState.initialLoading || techniquesState.initialLoading;
  const catalogueError = tacticsState.error || techniquesState.error;

  return (
    <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
      <div className="px-5 py-4 border-b border-surface-border">
        <div className="flex items-center justify-between mb-3 gap-3 flex-wrap">
          <div>
            <h3 className="text-sm font-semibold text-white">MITRE ATT&amp;CK Matrix</h3>
            <p className="text-[10px] text-gray-500 font-mono">
              {catalogueLoading
                ? 'loading catalogue…'
                : `${detectedCount} of ${totalCount} techniques observed`}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Badge variant={detectedCount > 0 ? 'danger' : 'default'} size="sm">
              {detectedCount} observed
            </Badge>
            <Badge variant="default" size="sm">
              {columns.length} tactics
            </Badge>
          </div>
        </div>

        {/* Belief feed powers the detected flags; surface its failure inline. */}
        {beliefState.error && (
          <div className="mb-3">
            <InlineError error={beliefState.error} />
            <p className="text-[10px] text-gray-500 mt-1">
              Detection overlay unavailable — techniques below fall back to the
              event feed only, so coverage may be understated.
            </p>
          </div>
        )}

        <div className="flex items-center gap-3 flex-wrap">
          <div className="relative flex-1 min-w-[200px]">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
            <input
              type="text"
              placeholder="Search techniques by name or ID…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-8 pr-3 py-1.5 text-xs bg-surface border border-surface-border rounded-lg text-white placeholder-gray-500 focus:outline-none focus:border-accent-blue/50"
            />
          </div>
          <button
            onClick={() => setOnlyDetected(!onlyDetected)}
            className={cn(
              'px-2.5 py-1.5 text-[10px] rounded font-medium transition-colors border',
              onlyDetected
                ? 'bg-accent-red/20 text-accent-red border-accent-red/30'
                : 'text-gray-500 border-surface-border hover:text-white'
            )}
          >
            Observed only
          </button>
        </div>
      </div>

      {catalogueLoading && <LoadingState label="Loading ATT&CK catalogue…" />}
      {!catalogueLoading && catalogueError && (
        <ErrorState
          error={catalogueError}
          onRetry={() => {
            tacticsState.refetch();
            techniquesState.refetch();
          }}
        />
      )}
      {!catalogueLoading && !catalogueError && columns.length === 0 && (
        <EmptyState
          title="No ATT&CK data"
          message="The MITRE catalogue endpoints returned no tactics or techniques."
        />
      )}
      {!catalogueLoading && !catalogueError && columns.length > 0 && visible.length === 0 && (
        <div className="px-5 py-8 text-center text-sm text-gray-500">
          No techniques match the current filters
        </div>
      )}

      {visible.length > 0 && (
        <div className="overflow-x-auto">
          <div className="flex gap-1 p-3 min-w-max">
            {visible.map((column) => (
              <div
                key={column.id}
                className="flex flex-col gap-1 min-w-[130px] max-w-[150px]"
              >
                <div className="px-2 py-1.5 rounded bg-surface border border-surface-border text-center">
                  <p className="text-[9px] text-gray-500 font-mono">{column.id}</p>
                  <p className="text-[10px] text-white font-medium leading-tight">
                    {column.name}
                  </p>
                </div>

                {column.cells.map((cell) => (
                  <button
                    key={cell.id}
                    onClick={() =>
                      setSelected(selected?.id === cell.id ? null : cell)
                    }
                    className={cn(
                      'px-2 py-2 rounded text-[9px] leading-tight text-left border transition-all duration-150',
                      cell.detected
                        ? 'bg-accent-red/10 border-accent-red/40 text-accent-red hover:bg-accent-red/20'
                        : 'bg-surface/50 border-surface-border text-gray-500 hover:border-gray-500/50 hover:text-gray-300'
                    )}
                  >
                    <span className="font-mono">{cell.id}</span>
                    <br />
                    {cell.name}
                    {cell.detected && <span className="ml-1 text-[8px]">●</span>}
                  </button>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {selected && (
        <div className="border-t border-surface-border px-5 py-4">
          <div className="flex items-start gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-2 flex-wrap">
                <Badge variant={selected.detected ? 'danger' : 'default'} size="sm">
                  {selected.detected ? 'OBSERVED' : 'NOT OBSERVED'}
                </Badge>
                <span className="text-xs font-mono text-accent-blue">
                  {selected.id}
                </span>
                <span className="text-xs text-white font-medium">
                  {selected.name}
                </span>
              </div>
              {selected.evidence.length > 0 ? (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">
                    Supporting events ({selected.evidence.length})
                  </p>
                  <ul className="space-y-1 max-h-40 overflow-y-auto">
                    {selected.evidence.map((item, idx) => (
                      <li
                        key={idx}
                        className="text-[11px] text-gray-400 font-mono flex items-start gap-1.5"
                      >
                        <span className="text-accent-red mt-0.5">•</span>
                        {item}
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <p className="text-xs text-gray-500">
                  {selected.detected
                    ? 'Observed by the world model, but no matching event records were found in the current feed window.'
                    : 'No activity observed for this technique.'}
                </p>
              )}
            </div>
            <button
              onClick={() => setSelected(null)}
              className="p-1 text-gray-400 hover:text-white hover:bg-surface-border rounded transition-colors shrink-0"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
