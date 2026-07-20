'use client';

import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { AgentStatusPanel } from '@/components/agents/AgentStatusPanel';
import { AgentConsole } from '@/components/agents/AgentConsole';

export default function AgentsPage() {
  return (
    <DashboardLayout>
      <div className="space-y-6">
        <div>
          <h1 className="text-xl font-bold text-white">Agents</h1>
          <p className="text-xs text-gray-500 mt-1">
            Registered defence agents and the live telemetry stream they act on.
          </p>
        </div>
        <AgentStatusPanel />
        <AgentConsole />
      </div>
    </DashboardLayout>
  );
}
