'use client';

import { cn } from '@/lib/utils';
import { api, Severity } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { MitreMatrix } from './MitreMatrix';
import {
  EmptyState,
  ErrorState,
  InlineError,
  LoadingState,
} from '@/components/ui/States';
import { AlertTriangle, Bug, Activity, Radio, Fingerprint } from 'lucide-react';

function StatTile({
  label,
  value,
  color,
  icon: Icon,
  loading,
}: {
  label: string;
  value: number | string;
  color: string;
  icon: typeof Bug;
  loading: boolean;
}) {
  return (
    <div className="bg-surface-card border border-surface-border rounded-xl p-4">
      <div className="flex items-center gap-3">
        <div className={cn('p-2 rounded-lg bg-surface', color)}>
          <Icon className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <p className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</p>
          {loading ? (
            <div className="h-6 w-12 rounded bg-surface-border/60 animate-pulse mt-1" />
          ) : (
            <p className={cn('text-lg font-bold font-mono', color)}>{value}</p>
          )}
        </div>
      </div>
    </div>
  );
}

/**
 * Threat intelligence overview.
 *
 * Previously this rendered hardcoded CVE, CISA KEV and threat-actor lists. The
 * API exposes no CVE or KEV feed, so those panels are gone rather than faked —
 * what remains is the real indicator feed, real event statistics, and campaign
 * attribution from the world model.
 */
export function ThreatIntelDashboard() {
  const stats = useApi(() => api.getThreatIntelStats(), [], 15000);
  const indicators = useApi(() => api.getIndicators({ page_size: 50 }), [], 10000);
  const belief = useApi(() => api.getAttackerBelief(), [], 10000);

  const s = stats.data;
  const bySeverity = s?.by_severity ?? {};

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-xl font-bold text-white">Threat Intelligence</h2>
        <p className="text-xs text-gray-500 mt-1">
          ATT&amp;CK coverage, live indicators, and campaign attribution.
        </p>
      </div>

      {stats.error && <InlineError error={stats.error} />}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatTile
          label="Total Events"
          value={s?.total_events ?? '—'}
          color="text-accent-blue"
          icon={Activity}
          loading={stats.initialLoading}
        />
        <StatTile
          label="Critical"
          value={bySeverity.critical ?? 0}
          color="text-accent-red"
          icon={AlertTriangle}
          loading={stats.initialLoading}
        />
        <StatTile
          label="High"
          value={bySeverity.high ?? 0}
          color="text-accent-orange"
          icon={Bug}
          loading={stats.initialLoading}
        />
        <StatTile
          label="Sources"
          value={Object.keys(s?.by_source ?? {}).length || '—'}
          color="text-accent-yellow"
          icon={Radio}
          loading={stats.initialLoading}
        />
      </div>

      <MitreMatrix />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Indicators */}
        <Card
          header={
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-white">Recent Indicators</h3>
              <Badge variant="default" size="sm">
                {indicators.data?.length ?? 0}
              </Badge>
            </div>
          }
        >
          <div className="-mx-5 -mb-5 max-h-[420px] overflow-y-auto">
            {indicators.initialLoading && <LoadingState label="Loading indicators…" />}
            {!indicators.initialLoading && indicators.error && (
              <ErrorState error={indicators.error} onRetry={indicators.refetch} />
            )}
            {!indicators.initialLoading &&
              !indicators.error &&
              (indicators.data?.length ?? 0) === 0 && (
                <EmptyState
                  title="No indicators"
                  message="No threat intel has been ingested yet."
                />
              )}
            {(indicators.data ?? []).map((event) => (
              <div
                key={event.id}
                className="px-5 py-3 border-b border-surface-border last:border-b-0 hover:bg-surface/30 transition-colors"
              >
                <div className="flex items-center gap-2 flex-wrap">
                  <SeverityBadge severity={event.severity as Severity} />
                  <span className="text-[10px] text-gray-500 font-mono">
                    {event.source}
                  </span>
                  <Badge variant="default" size="sm">
                    {event.category}
                  </Badge>
                </div>
                <p className="text-xs text-white font-medium mt-1">{event.title}</p>
                <p className="text-[11px] text-gray-400 mt-0.5">{event.description}</p>
                <div className="flex items-center gap-2 mt-1 flex-wrap">
                  <span className="text-[10px] text-gray-600 font-mono">
                    {new Date(event.timestamp).toLocaleString()}
                  </span>
                  {event.tags?.map((tag) => (
                    <span
                      key={tag}
                      className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-border/60 text-gray-400"
                    >
                      {tag}
                    </span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </Card>

        {/* Attribution */}
        <Card
          header={
            <div className="flex items-center gap-2">
              <Fingerprint className="h-4 w-4 text-accent-orange" />
              <h3 className="text-sm font-semibold text-white">Campaign Attribution</h3>
            </div>
          }
        >
          {belief.initialLoading && <LoadingState label="Loading attribution…" />}
          {!belief.initialLoading && belief.error && (
            <ErrorState error={belief.error} onRetry={belief.refetch} />
          )}
          {belief.data && !belief.error && (
            <div className="space-y-4">
              {belief.data.campaign_match?.actor ? (
                <div className="px-3 py-2.5 rounded-lg bg-accent-orange/10 border border-accent-orange/25">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm text-white font-medium">
                      {belief.data.campaign_match.actor}
                    </p>
                    <Badge variant="warning" size="sm">
                      {Math.round(belief.data.campaign_match.confidence * 100)}%
                      confidence
                    </Badge>
                  </div>
                  <p className="text-[11px] text-gray-400 mt-1">
                    Matched on observed technique sequence.
                  </p>
                </div>
              ) : (
                <p className="text-xs text-gray-500">
                  No campaign attributed yet.
                </p>
              )}

              {belief.data.observed_techniques?.length > 0 && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">
                    Observed techniques ({belief.data.observed_techniques.length})
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {belief.data.observed_techniques.map((technique) => (
                      <span
                        key={technique}
                        className="text-[10px] font-mono px-2 py-0.5 rounded bg-accent-red/10 text-accent-red border border-accent-red/25"
                      >
                        {technique}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {belief.data.capabilities?.length > 0 && (
                <div>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1.5">
                    Demonstrated capabilities
                  </p>
                  <div className="flex flex-wrap gap-1">
                    {belief.data.capabilities.map((cap) => (
                      <Badge key={cap.capability} variant="danger" size="sm">
                        {cap.capability}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
