'use client';

import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { StatsCards } from '@/components/dashboard/StatsCards';
import { AlertsPanel } from '@/components/dashboard/AlertsPanel';
import { ThreatTimeline } from '@/components/dashboard/ThreatTimeline';
import { NetworkMap } from '@/components/dashboard/NetworkMap';
import { AttackPredictionCard } from '@/components/dashboard/AttackPredictionCard';

export default function DashboardPage() {
  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-white">Operations Dashboard</h1>
          <p className="text-xs text-gray-500 mt-1">
            Live posture across incidents, assets and agents. Polls every 5s.
          </p>
        </div>

        <StatsCards />

        <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
          <div className="xl:col-span-2 space-y-6">
            <NetworkMap />
            <ThreatTimeline />
          </div>
          <div className="space-y-6">
            <AttackPredictionCard />
            <AlertsPanel />
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
