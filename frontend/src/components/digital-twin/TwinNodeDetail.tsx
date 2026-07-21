'use client';

import { cn } from '@/lib/utils';
import { api, Asset } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import { InlineError, LoadingState } from '@/components/ui/States';
import {
  X,
  Server,
  Monitor,
  Shield,
  Database,
  Wifi,
  Activity,
  Box,
  Cpu,
  HardDrive,
} from 'lucide-react';

const typeIcons: Record<string, React.ReactNode> = {
  server: <Server className="h-4 w-4" />,
  database: <Database className="h-4 w-4" />,
  workstation: <Monitor className="h-4 w-4" />,
  network_device: <Wifi className="h-4 w-4" />,
  security_appliance: <Shield className="h-4 w-4" />,
};

function Gauge({
  label,
  value,
  icon,
}: {
  label: string;
  value: number | null;
  icon: React.ReactNode;
}) {
  if (value === null || value === undefined) return null;
  const color =
    value > 85 ? 'bg-accent-red' : value > 60 ? 'bg-accent-yellow' : 'bg-accent-green';
  return (
    <div>
      <div className="flex items-center justify-between mb-1">
        <span className="flex items-center gap-1.5 text-[10px] text-gray-400">
          {icon}
          {label}
        </span>
        <span className="text-[10px] font-mono text-white">{value.toFixed(0)}%</span>
      </div>
      <div className="h-1.5 bg-surface rounded-full overflow-hidden">
        <div
          className={cn('h-full rounded-full transition-all', color)}
          style={{ width: `${Math.min(value, 100)}%` }}
        />
      </div>
    </div>
  );
}

/**
 * Asset detail sourced from GET /digital-twin/assets/{id} plus its live state.
 * Connected assets, recent events and predicted attack paths are no longer
 * shown here — the previous version hardcoded all three.
 */
export function TwinNodeDetail({
  asset,
  onClose,
}: {
  asset: Asset;
  onClose: () => void;
}) {
  const stateQuery = useApi(() => api.getAssetState(asset.id), [asset.id], 5000);
  const live = stateQuery.data;

  const criticalityVariant =
    asset.criticality === 'critical'
      ? 'danger'
      : asset.criticality === 'high'
        ? 'warning'
        : asset.criticality === 'medium'
          ? 'info'
          : 'success';

  return (
    <div className="bg-surface-card/95 backdrop-blur-md border border-surface-border rounded-xl shadow-2xl max-h-[560px] overflow-y-auto">
      <div className="flex items-center justify-between px-4 py-3 border-b border-surface-border sticky top-0 bg-surface-card/95 backdrop-blur-md z-10">
        <div className="flex items-center gap-2 min-w-0">
          <div className="p-1.5 rounded bg-accent-blue/15 text-accent-blue shrink-0">
            {typeIcons[asset.asset_type] || <Box className="h-4 w-4" />}
          </div>
          <div className="min-w-0">
            <h4 className="text-sm font-semibold text-white truncate">{asset.name}</h4>
            <p className="text-[10px] text-gray-500">
              {asset.asset_type.replace(/_/g, ' ')}
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="p-1 text-gray-400 hover:text-white hover:bg-surface-border rounded transition-colors shrink-0"
        >
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="p-4 space-y-4">
        <div className="grid grid-cols-2 gap-3">
          <div className="px-3 py-2 rounded-lg bg-surface/50">
            <p className="text-[10px] text-gray-500 mb-0.5">Criticality</p>
            <Badge variant={criticalityVariant} size="sm">
              {asset.criticality}
            </Badge>
          </div>
          <div className="px-3 py-2 rounded-lg bg-surface/50">
            <p className="text-[10px] text-gray-500 mb-0.5">IP Address</p>
            <p className="text-xs text-white font-mono truncate">
              {asset.ip_address || '—'}
            </p>
          </div>
        </div>

        <div className="space-y-2">
          {[
            ['Hostname', asset.hostname],
            ['Domain', asset.domain],
            ['OS', asset.os ? `${asset.os} ${asset.os_version ?? ''}`.trim() : null],
            ['Location', asset.location],
            ['Department', asset.department],
            ['Owner', asset.owner],
          ]
            .filter(([, value]) => value)
            .map(([label, value]) => (
              <div key={label as string} className="flex items-start gap-2">
                <span className="text-[10px] text-gray-500 w-20 shrink-0">
                  {label as string}
                </span>
                <span className="text-xs text-gray-200 font-mono min-w-0 break-all">
                  {value as string}
                </span>
              </div>
            ))}
        </div>

        {asset.tags?.length > 0 && (
          <div className="flex flex-wrap gap-1">
            {asset.tags.map((tag) => (
              <Badge key={tag} variant="default" size="sm">
                {tag}
              </Badge>
            ))}
          </div>
        )}

        {/* Live telemetry */}
        <div className="pt-2 border-t border-surface-border">
          <p className="text-xs text-gray-400 font-medium mb-2">Live State</p>
          {stateQuery.initialLoading && <LoadingState label="Reading state…" />}
          {stateQuery.error && <InlineError error={stateQuery.error} />}
          {live && !stateQuery.error && (
            <div className="space-y-3">
              <div className="flex items-center gap-2">
                <span className="text-[10px] text-gray-500">Status</span>
                <Badge
                  variant={live.current_status === 'healthy' ? 'success' : 'warning'}
                  size="sm"
                >
                  {live.current_status}
                </Badge>
              </div>
              <Gauge
                label="CPU"
                value={live.cpu_usage}
                icon={<Cpu className="h-3 w-3" />}
              />
              <Gauge
                label="Memory"
                value={live.memory_usage}
                icon={<Activity className="h-3 w-3" />}
              />
              <Gauge
                label="Disk"
                value={live.disk_usage}
                icon={<HardDrive className="h-3 w-3" />}
              />

              {live.open_ports && live.open_ports.length > 0 && (
                <div>
                  <p className="text-[10px] text-gray-500 mb-1">Open ports</p>
                  <div className="flex flex-wrap gap-1">
                    {live.open_ports.map((port) => (
                      <span
                        key={port}
                        className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-surface-border/60 text-gray-300"
                      >
                        {port}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {live.vulnerabilities && live.vulnerabilities.length > 0 && (
                <div>
                  <p className="text-[10px] text-accent-red mb-1">
                    {live.vulnerabilities.length} vulnerabilities
                  </p>
                </div>
              )}

              <p className="text-[10px] text-gray-600 font-mono">
                updated {new Date(live.last_updated).toLocaleTimeString()}
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
