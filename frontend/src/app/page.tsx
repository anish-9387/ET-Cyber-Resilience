export default function DashboardPage() {
  return (
    <main className="min-h-screen bg-surface text-foreground">
      <header className="border-b border-surface-border px-6 py-4">
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold text-accent-green">
            Sentinel-X
          </h1>
          <span className="text-sm text-gray-400">
            Cyber Resilience Platform
          </span>
        </div>
      </header>
      <section className="p-6">
        <div className="grid grid-cols-1 gap-6 md:grid-cols-2 lg:grid-cols-4">
          <div className="rounded-lg border border-surface-border bg-surface-card p-4">
            <h3 className="text-sm font-medium text-gray-400">
              Active Agents
            </h3>
            <p className="mt-2 text-3xl font-bold text-accent-cyan">0</p>
          </div>
          <div className="rounded-lg border border-surface-border bg-surface-card p-4">
            <h3 className="text-sm font-medium text-gray-400">
              Incidents
            </h3>
            <p className="mt-2 text-3xl font-bold text-accent-red">0</p>
          </div>
          <div className="rounded-lg border border-surface-border bg-surface-card p-4">
            <h3 className="text-sm font-medium text-gray-400">
              Assets Monitored
            </h3>
            <p className="mt-2 text-3xl font-bold text-accent-green">0</p>
          </div>
          <div className="rounded-lg border border-surface-border bg-surface-card p-4">
            <h3 className="text-sm font-medium text-gray-400">
              System Health
            </h3>
            <p className="mt-2 text-3xl font-bold text-accent-yellow">
              N/A
            </p>
          </div>
        </div>
      </section>
    </main>
  );
}
