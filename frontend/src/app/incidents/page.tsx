'use client';

import { useState } from 'react';
import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { IncidentList } from '@/components/incidents/IncidentList';
import { IncidentDetail } from '@/components/incidents/IncidentDetail';

export default function IncidentsPage() {
  const [selectedId, setSelectedId] = useState<string | null>(null);

  return (
    <DashboardLayout>
      {selectedId ? (
        <IncidentDetail
          incidentId={selectedId}
          onBack={() => setSelectedId(null)}
        />
      ) : (
        <div className="space-y-6">
          <div>
            <h1 className="text-xl font-bold text-white">Incidents</h1>
            <p className="text-xs text-gray-500 mt-1">
              Select an incident to see its full timeline, indicators and
              ATT&amp;CK mapping.
            </p>
          </div>
          <IncidentList onSelect={setSelectedId} selectedId={selectedId} />
        </div>
      )}
    </DashboardLayout>
  );
}
