'use client';

import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { SettingsPanel } from '@/components/settings/SettingsPanel';

export default function SettingsPage() {
  return (
    <DashboardLayout>
      <SettingsPanel />
    </DashboardLayout>
  );
}
