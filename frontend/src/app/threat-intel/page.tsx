'use client';

import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { ThreatIntelDashboard } from '@/components/threat-intel/ThreatIntelDashboard';

export default function ThreatIntelPage() {
  return (
    <DashboardLayout>
      <ThreatIntelDashboard />
    </DashboardLayout>
  );
}
