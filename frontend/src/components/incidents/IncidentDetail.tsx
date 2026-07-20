'use client';

import { api, Criticality } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { SeverityBadge } from '@/components/ui/SeverityBadge';
import { Badge } from '@/components/ui/Badge';
import { Timeline } from '@/components/ui/Timeline';
import { Card } from '@/components/ui/Card';
import {
  EmptyState,
  ErrorState,
  InlineError,
  LoadingState,
} from '@/components/ui/States';
import { ArrowLeft, Activity, Monitor, Crosshair, Fingerprint } from 'lucide-react';

const timelineColor = (action: string): 'red' | 'orange' | 'yellow' | 'cyan' | 'green' => {
  const a = action.toLowerCase();
  if (a.includes('creat') || a.includes('detect')) return 'cyan';
  if (a.includes('escalat') || a.includes('sever')) return 'red';
  if (a.includes('contain') || a.includes('respond')) return 'orange';
  if (a.includes('resolv') || a.includes('clos')) return 'green';
  return 'yellow';
};

export function IncidentDetail({
  incidentId,
  onBack,
}: {
  incidentId: string;
  onBack?: () => void;
}) {
  const detail = useApi(() => api.getIncident(incidentId), [incidentId]);
  const timeline = useApi(() => api.getIncidentTimeline(incidentId), [incidentId]);

  if (detail.initialLoading) return <LoadingState label="Loading incident…" />;
  if (detail.error)
    return <ErrorState error={detail.error} onRetry={detail.refetch} />;

  const incident = detail.data;
  if (!incident) return <EmptyState title="Incident not found" message="" />;

  const events = (timeline.data ?? []).map((entry, idx) => ({
    id: `${entry.timestamp}-${idx}`,
    timestamp: new Date(entry.timestamp).toLocaleString(),
    title: entry.action,
    description: `${entry.description}${entry.actor ? ` — ${entry.actor}` : ''}`,
    color: timelineColor(entry.action),
  }));

  return (
    <div className="space-y-6">
      <div>
        {onBack && (
          <button
            onClick={onBack}
            className="flex items-center gap-1 text-xs text-gray-400 hover:text-white transition-colors mb-3"
          >
            <ArrowLeft className="h-3.5 w-3.5" />
            Back to incidents
          </button>
        )}
        <div className="flex items-start justify-between gap-3 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-3 flex-wrap">
              <h2 className="text-xl font-bold text-white">{incident.title}</h2>
              <SeverityBadge severity={incident.severity as Criticality} size="md" />
            </div>
            <div className="flex items-center gap-3 mt-2 flex-wrap">
              <span className="text-xs font-mono text-accent-cyan">{incident.id}</span>
              <span className="text-xs text-gray-500">·</span>
              <span className="text-xs text-gray-400">
                {incident.incident_type.replace(/_/g, ' ')}
              </span>
              <span className="text-xs text-gray-500">·</span>
              <span className="text-xs text-gray-500">
                {new Date(incident.created_at).toLocaleString()}
              </span>
              <Badge variant="warning" size="sm">
                {incident.status.replace(/_/g, ' ')}
              </Badge>
              <Badge variant="default" size="sm">
                {incident.priority.toUpperCase()}
              </Badge>
            </div>
          </div>
        </div>
        <p className="text-xs text-gray-400 mt-3 max-w-3xl">{incident.description}</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-6">
          <Card
            header={
              <div className="flex items-center gap-2">
                <Activity className="h-4 w-4 text-accent-cyan" />
                <h3 className="text-sm font-semibold text-white">Incident Timeline</h3>
                {events.length > 0 && (
                  <Badge variant="default" size="sm">
                    {events.length} entries
                  </Badge>
                )}
              </div>
            }
          >
            {timeline.initialLoading && <LoadingState label="Loading timeline…" />}
            {timeline.error && <InlineError error={timeline.error} />}
            {!timeline.initialLoading && !timeline.error && events.length === 0 && (
              <EmptyState
                title="No timeline entries"
                message="No actions have been recorded against this incident."
                className="py-8"
              />
            )}
            {events.length > 0 && <Timeline events={events} />}
          </Card>

          {incident.mitre_techniques?.length > 0 && (
            <Card
              header={
                <div className="flex items-center gap-2">
                  <Crosshair className="h-4 w-4 text-accent-orange" />
                  <h3 className="text-sm font-semibold text-white">
                    MITRE ATT&amp;CK Techniques
                  </h3>
                </div>
              }
            >
              <div className="flex flex-wrap gap-1.5">
                {incident.mitre_techniques.map((technique) => (
                  <span
                    key={technique}
                    className="text-[11px] font-mono px-2 py-1 rounded bg-accent-orange/10 text-accent-orange border border-accent-orange/25"
                  >
                    {technique}
                  </span>
                ))}
              </div>
            </Card>
          )}

          {incident.indicators?.length > 0 && (
            <Card
              header={
                <div className="flex items-center gap-2">
                  <Fingerprint className="h-4 w-4 text-accent-cyan" />
                  <h3 className="text-sm font-semibold text-white">Indicators</h3>
                  <Badge variant="default" size="sm">
                    {incident.indicators.length}
                  </Badge>
                </div>
              }
            >
              <div className="space-y-1">
                {incident.indicators.map((indicator) => (
                  <p
                    key={indicator}
                    className="text-xs font-mono text-gray-300 px-2.5 py-1.5 rounded bg-surface/60"
                  >
                    {indicator}
                  </p>
                ))}
              </div>
            </Card>
          )}
        </div>

        <div className="space-y-4">
          <Card
            header={
              <div className="flex items-center gap-2">
                <Monitor className="h-4 w-4 text-accent-red" />
                <h3 className="text-sm font-semibold text-white">Affected Assets</h3>
              </div>
            }
          >
            {incident.affected_assets?.length ? (
              <div className="space-y-1.5">
                {incident.affected_assets.map((asset) => (
                  <p
                    key={asset}
                    className="text-xs font-mono text-white px-2.5 py-1.5 rounded bg-surface/60"
                  >
                    {asset}
                  </p>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-500">No assets recorded.</p>
            )}
          </Card>

          <Card header={<h3 className="text-sm font-semibold text-white">Details</h3>}>
            <div className="space-y-2.5">
              {[
                ['Status', incident.status.replace(/_/g, ' ')],
                ['Priority', incident.priority.toUpperCase()],
                ['Source', incident.source || '—'],
                ['Assigned to', incident.assigned_to || 'Unassigned'],
                ['Created by', incident.created_by || '—'],
                ['Updated', new Date(incident.updated_at).toLocaleString()],
                [
                  'Resolved',
                  incident.resolved_at
                    ? new Date(incident.resolved_at).toLocaleString()
                    : 'Not resolved',
                ],
              ].map(([label, value]) => (
                <div key={label} className="flex items-start gap-2">
                  <span className="text-[10px] text-gray-500 w-24 shrink-0 uppercase tracking-wider">
                    {label}
                  </span>
                  <span className="text-xs text-gray-200 min-w-0">{value}</span>
                </div>
              ))}
            </div>
            {incident.tags?.length > 0 && (
              <div className="mt-3 pt-3 border-t border-surface-border flex flex-wrap gap-1">
                {incident.tags.map((tag) => (
                  <Badge key={tag} variant="default" size="sm">
                    {tag}
                  </Badge>
                ))}
              </div>
            )}
          </Card>

          {incident.resolution_notes && (
            <Card
              header={
                <h3 className="text-sm font-semibold text-white">Resolution Notes</h3>
              }
            >
              <p className="text-xs text-gray-300">{incident.resolution_notes}</p>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
