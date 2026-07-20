'use client';

import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { DigitalTwinView } from '@/components/digital-twin/DigitalTwinView';
import { api, Criticality } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Badge } from '@/components/ui/Badge';
import { EmptyState, ErrorState, LoadingState } from '@/components/ui/States';
import { cn } from '@/lib/utils';

export default function DigitalTwinPage() {
  const assets = useApi(() => api.getAssets(), [], 15000);
  const list = assets.data ?? [];

  const byCriticality = list.reduce<Record<string, number>>((acc, asset) => {
    acc[asset.criticality] = (acc[asset.criticality] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div>
            <h1 className="text-xl font-bold text-white">Digital Twin</h1>
            <p className="text-xs text-gray-500 mt-1">
              A live 3D model of the estate. Click any node for its live state.
            </p>
          </div>
          {list.length > 0 && (
            <div className="flex items-center gap-2 flex-wrap">
              {(['critical', 'high', 'medium', 'low'] as Criticality[]).map((tier) => (
                <div
                  key={tier}
                  className="px-3 py-1.5 rounded-lg bg-surface-card border border-surface-border"
                >
                  <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                    {tier}
                  </p>
                  <p
                    className={cn(
                      'text-sm font-bold font-mono',
                      tier === 'critical' && 'text-accent-red',
                      tier === 'high' && 'text-accent-orange',
                      tier === 'medium' && 'text-accent-yellow',
                      tier === 'low' && 'text-accent-green'
                    )}
                  >
                    {byCriticality[tier] ?? 0}
                  </p>
                </div>
              ))}
            </div>
          )}
        </div>

        <DigitalTwinView />

        {/* Full inventory, including assets with no relationships (which the
            graph endpoint omits). */}
        <div className="bg-surface-card border border-surface-border rounded-xl overflow-hidden">
          <div className="px-5 py-3.5 border-b border-surface-border flex items-center justify-between gap-2 flex-wrap">
            <h3 className="text-sm font-semibold text-white">
              Asset Inventory
              {list.length > 0 && (
                <span className="text-[10px] text-gray-500 font-mono ml-2">
                  {list.length} assets
                </span>
              )}
            </h3>
            <p className="text-[10px] text-gray-500 font-mono">
              GET /digital-twin/assets
            </p>
          </div>

          {assets.initialLoading && <LoadingState label="Loading assets…" />}
          {!assets.initialLoading && assets.error && (
            <ErrorState error={assets.error} onRetry={assets.refetch} />
          )}
          {!assets.initialLoading && !assets.error && list.length === 0 && (
            <EmptyState
              title="No assets registered"
              message="Add assets via POST /digital-twin/assets to model the estate."
            />
          )}

          {list.length > 0 && (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-surface-border bg-surface/50">
                    {['Name', 'Type', 'IP', 'OS', 'Criticality', 'Owner'].map((h) => (
                      <th
                        key={h}
                        className="px-4 py-3 text-left font-medium text-gray-500 uppercase tracking-wider whitespace-nowrap"
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {list.map((asset) => (
                    <tr
                      key={asset.id}
                      className="border-b border-surface-border hover:bg-surface/30 transition-colors"
                    >
                      <td className="px-4 py-3 font-medium text-white">
                        {asset.name}
                      </td>
                      <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                        {asset.asset_type.replace(/_/g, ' ')}
                      </td>
                      <td className="px-4 py-3 text-gray-500 font-mono whitespace-nowrap">
                        {asset.ip_address || '—'}
                      </td>
                      <td className="px-4 py-3 text-gray-400 whitespace-nowrap">
                        {asset.os || '—'}
                      </td>
                      <td className="px-4 py-3">
                        <Badge
                          variant={
                            asset.criticality === 'critical'
                              ? 'danger'
                              : asset.criticality === 'high'
                                ? 'warning'
                                : asset.criticality === 'medium'
                                  ? 'info'
                                  : 'success'
                          }
                          size="sm"
                        >
                          {asset.criticality}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-gray-400">
                        {asset.owner || '—'}
                      </td>
                    </tr>
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
