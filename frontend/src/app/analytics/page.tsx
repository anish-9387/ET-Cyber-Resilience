'use client';

import { useState } from 'react';
import {
  BarChart,
  Bar,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts';
import { DashboardLayout } from '@/components/dashboard/DashboardLayout';
import { api, ApiError } from '@/lib/api';
import { useApi } from '@/lib/useApi';
import { Card } from '@/components/ui/Card';
import { Badge } from '@/components/ui/Badge';
import { Button } from '@/components/ui/Button';
import {
  EmptyState,
  ErrorState,
  InlineError,
  LoadingState,
} from '@/components/ui/States';
import { cn } from '@/lib/utils';
import {
  BarChart3,
  Award,
  Target,
  Zap,
  Timer,
  Play,
  FlaskConical,
} from 'lucide-react';

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#06b6d4',
  info: '#64748b',
};

const CHART_COLORS = ['#06b6d4', '#22c55e', '#eab308', '#f97316', '#ef4444', '#a855f7'];

const tooltipStyle = {
  backgroundColor: '#111827',
  border: '1px solid #1e293b',
  borderRadius: 8,
  fontSize: 11,
};

function toChartData(record: Record<string, number> | null | undefined) {
  if (!record) return [];
  return Object.entries(record).map(([name, value]) => ({ name, value }));
}

/* -------------------------------------------------------------------------- */
/* Evaluation — the judged metrics                                             */
/* -------------------------------------------------------------------------- */

function MetricTile({
  label,
  value,
  suffix = '',
  color,
  hint,
}: {
  label: string;
  value: number | string | null;
  suffix?: string;
  color: string;
  hint?: string;
}) {
  return (
    <div className="px-4 py-3 rounded-lg bg-surface/60 border border-surface-border">
      <p className="text-[9px] text-gray-500 uppercase tracking-wider">{label}</p>
      <p className={cn('text-2xl font-bold font-mono mt-0.5', color)}>
        {value === null || value === undefined ? '—' : value}
        {value !== null && value !== undefined && (
          <span className="text-sm">{suffix}</span>
        )}
      </p>
      {hint && <p className="text-[9px] text-gray-600 mt-0.5">{hint}</p>}
    </div>
  );
}

function EvaluationSection() {
  const detection = useApi(() => api.getDetectionEval(), []);
  const attribution = useApi(() => api.getAttributionEval(), []);
  const coverage = useApi(() => api.getResponseCoverage(), []);
  const timing = useApi(() => api.getMttdMttr(), []);

  const [running, setRunning] = useState(false);
  const [runError, setRunError] = useState<ApiError | null>(null);

  const rerun = async () => {
    setRunning(true);
    setRunError(null);
    try {
      await api.runEvaluation();
      detection.refetch();
      attribution.refetch();
      coverage.refetch();
      timing.refetch();
    } catch (err) {
      setRunError(
        err instanceof ApiError
          ? err
          : new ApiError('Evaluation run failed', 0, '/evaluation/run')
      );
    } finally {
      setRunning(false);
    }
  };

  const d = detection.data;
  const a = attribution.data;
  const c = coverage.data;
  const t = timing.data;

  const pct = (v: number | undefined) =>
    v === undefined || v === null ? null : (v * 100).toFixed(1);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2.5">
          <Award className="h-5 w-5 text-accent-green" />
          <div>
            <h2 className="text-base font-bold text-white">Evaluation Metrics</h2>
            <p className="text-[10px] text-gray-500">
              Measured performance against a labelled benchmark. Sourced from{' '}
              <span className="font-mono">/evaluation/*</span> — every figure is
              computed server-side, none are illustrative.
            </p>
          </div>
        </div>
        <Button
          size="sm"
          variant="secondary"
          loading={running}
          onClick={rerun}
          icon={<Play className="h-3.5 w-3.5" />}
        >
          Re-run evaluation
        </Button>
      </div>

      {runError && <InlineError error={runError} />}

      {/* Detection */}
      <Card
        header={
          <div className="flex items-center gap-2 flex-wrap">
            <Target className="h-4 w-4 text-accent-cyan" />
            <h3 className="text-sm font-semibold text-white">Anomaly Detection</h3>
            {d && (
              <Badge variant="info" size="sm">
                {d.dataset} · n={d.samples}
              </Badge>
            )}
            <span className="text-[10px] text-gray-500 font-mono ml-auto">
              GET /evaluation/detection
            </span>
          </div>
        }
      >
        {detection.initialLoading && <LoadingState label="Loading detection metrics…" />}
        {!detection.initialLoading && detection.error && (
          <ErrorState error={detection.error} onRetry={detection.refetch} />
        )}
        {d && !detection.error && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3">
              <MetricTile
                label="Precision"
                value={pct(d.precision)}
                suffix="%"
                color="text-accent-green"
              />
              <MetricTile
                label="Recall"
                value={pct(d.recall)}
                suffix="%"
                color="text-accent-cyan"
              />
              <MetricTile
                label="F1 Score"
                value={pct(d.f1)}
                suffix="%"
                color="text-accent-green"
              />
              <MetricTile
                label="False Positive Rate"
                value={pct(d.fpr)}
                suffix="%"
                color="text-accent-yellow"
                hint="lower is better"
              />
              <MetricTile
                label="ROC AUC"
                value={d.roc_auc?.toFixed(3)}
                color="text-accent-cyan"
              />
            </div>
            <div className="grid grid-cols-4 gap-2">
              {[
                ['True Positives', d.tp, 'text-accent-green'],
                ['False Positives', d.fp, 'text-accent-red'],
                ['True Negatives', d.tn, 'text-accent-green'],
                ['False Negatives', d.fn, 'text-accent-red'],
              ].map(([label, value, color]) => (
                <div
                  key={label as string}
                  className="px-3 py-2 rounded-lg bg-surface/40 text-center"
                >
                  <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                    {label as string}
                  </p>
                  <p className={cn('text-sm font-bold font-mono', color as string)}>
                    {value as number}
                  </p>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>

      {/* Attribution */}
      <Card
        header={
          <div className="flex items-center gap-2 flex-wrap">
            <FlaskConical className="h-4 w-4 text-accent-orange" />
            <h3 className="text-sm font-semibold text-white">
              MITRE Attribution Accuracy
            </h3>
            <span className="text-[10px] text-gray-500 font-mono ml-auto">
              GET /evaluation/attribution
            </span>
          </div>
        }
      >
        {attribution.initialLoading && <LoadingState label="Loading attribution…" />}
        {!attribution.initialLoading && attribution.error && (
          <ErrorState error={attribution.error} onRetry={attribution.refetch} />
        )}
        {a && !attribution.error && (
          <div className="space-y-4">
            <div className="grid grid-cols-2 gap-3">
              <MetricTile
                label="Technique-level accuracy"
                value={pct(a.technique_accuracy)}
                suffix="%"
                color="text-accent-orange"
              />
              <MetricTile
                label="Tactic-level accuracy"
                value={pct(a.tactic_accuracy)}
                suffix="%"
                color="text-accent-orange"
              />
            </div>
            {a.per_technique?.length > 0 && (
              <div style={{ height: 240 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={a.per_technique.map((p) => ({
                      name: p.technique_id,
                      accuracy: Number((p.accuracy * 100).toFixed(1)),
                    }))}
                    margin={{ top: 5, right: 8, left: -22, bottom: 40 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis
                      dataKey="name"
                      stroke="#475569"
                      tick={{ fontSize: 9 }}
                      angle={-45}
                      textAnchor="end"
                      interval={0}
                    />
                    <YAxis stroke="#475569" tick={{ fontSize: 9 }} domain={[0, 100]} />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Bar dataKey="accuracy" fill="#f97316" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
            )}
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Response coverage */}
        <Card
          header={
            <div className="flex items-center gap-2 flex-wrap">
              <Zap className="h-4 w-4 text-accent-green" />
              <h3 className="text-sm font-semibold text-white">
                Response Automation Coverage
              </h3>
            </div>
          }
        >
          {coverage.initialLoading && <LoadingState label="Loading coverage…" />}
          {!coverage.initialLoading && coverage.error && (
            <ErrorState error={coverage.error} onRetry={coverage.refetch} />
          )}
          {c && !coverage.error && (
            <div className="space-y-4">
              <MetricTile
                label="Overall automation coverage"
                value={c.coverage_pct?.toFixed(1)}
                suffix="%"
                color="text-accent-green"
                hint={`${c.automatable} of ${c.total_steps} playbook steps automatable`}
              />
              {c.per_playbook?.length > 0 && (
                <div className="space-y-2">
                  {c.per_playbook.map((pb) => (
                    <div key={pb.playbook}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-[11px] text-gray-300 truncate">
                          {pb.playbook}
                        </span>
                        <span className="text-[10px] font-mono text-accent-green shrink-0">
                          {pb.coverage_pct.toFixed(0)}%{' '}
                          <span className="text-gray-600">
                            ({pb.automatable}/{pb.total_steps})
                          </span>
                        </span>
                      </div>
                      <div className="h-1.5 bg-surface rounded-full overflow-hidden">
                        <div
                          className="h-full rounded-full bg-accent-green transition-all"
                          style={{ width: `${pb.coverage_pct}%` }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}
        </Card>

        {/* MTTD / MTTR */}
        <Card
          header={
            <div className="flex items-center gap-2 flex-wrap">
              <Timer className="h-4 w-4 text-accent-cyan" />
              <h3 className="text-sm font-semibold text-white">
                MTTD / MTTR vs Baseline
              </h3>
            </div>
          }
        >
          {timing.initialLoading && <LoadingState label="Loading timings…" />}
          {!timing.initialLoading && timing.error && (
            <ErrorState error={timing.error} onRetry={timing.refetch} />
          )}
          {t && !timing.error && (
            <div className="space-y-4">
              <div style={{ height: 200 }}>
                <ResponsiveContainer width="100%" height="100%">
                  <BarChart
                    data={[
                      {
                        name: 'MTTD',
                        Baseline: t.baseline_mttd_minutes,
                        Sentinel: t.sentinel_mttd_minutes,
                      },
                      {
                        name: 'MTTR',
                        Baseline: t.baseline_mttr_minutes,
                        Sentinel: t.sentinel_mttr_minutes,
                      },
                    ]}
                    margin={{ top: 5, right: 8, left: -20, bottom: 0 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                    <XAxis dataKey="name" stroke="#475569" tick={{ fontSize: 10 }} />
                    <YAxis
                      stroke="#475569"
                      tick={{ fontSize: 9 }}
                      label={{
                        value: 'minutes',
                        angle: -90,
                        position: 'insideLeft',
                        fill: '#475569',
                        fontSize: 9,
                      }}
                    />
                    <Tooltip contentStyle={tooltipStyle} />
                    <Legend wrapperStyle={{ fontSize: 10 }} />
                    <Bar dataKey="Baseline" fill="#64748b" radius={[3, 3, 0, 0]} />
                    <Bar dataKey="Sentinel" fill="#06b6d4" radius={[3, 3, 0, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </div>
              <div className="grid grid-cols-2 gap-3">
                <MetricTile
                  label="MTTD improvement"
                  value={t.mttd_improvement_pct?.toFixed(1)}
                  suffix="%"
                  color="text-accent-green"
                  hint={`${t.baseline_mttd_minutes}m → ${t.sentinel_mttd_minutes}m`}
                />
                <MetricTile
                  label="MTTR improvement"
                  value={t.mttr_improvement_pct?.toFixed(1)}
                  suffix="%"
                  color="text-accent-green"
                  hint={`${t.baseline_mttr_minutes}m → ${t.sentinel_mttr_minutes}m`}
                />
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

/* -------------------------------------------------------------------------- */
/* Operational analytics                                                       */
/* -------------------------------------------------------------------------- */

function OperationalAnalytics() {
  const [days, setDays] = useState(7);
  const trend = useApi(() => api.getIncidentTrend(days), [days], 30000);
  const bySeverity = useApi(() => api.getIncidentsBySeverity(), [], 30000);
  const byType = useApi(() => api.getIncidentsByType(), [], 30000);
  const assetsByType = useApi(() => api.getAssetsByType(), [], 30000);
  const mttr = useApi(() => api.getMttr(30), [], 30000);

  const severityData = toChartData(bySeverity.data);
  const typeData = toChartData(byType.data);
  const assetData = toChartData(assetsByType.data);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2.5">
          <BarChart3 className="h-5 w-5 text-accent-cyan" />
          <h2 className="text-base font-bold text-white">Operational Analytics</h2>
        </div>
        <div className="flex items-center gap-1.5">
          {[7, 14, 30, 90].map((d) => (
            <button
              key={d}
              onClick={() => setDays(d)}
              className={cn(
                'px-2.5 py-1 text-[10px] rounded font-medium transition-colors font-mono',
                days === d
                  ? 'bg-accent-cyan/20 text-accent-cyan border border-accent-cyan/30'
                  : 'text-gray-500 hover:text-white hover:bg-surface-border'
              )}
            >
              {d}d
            </button>
          ))}
        </div>
      </div>

      <Card
        header={
          <h3 className="text-sm font-semibold text-white">
            Incident Trend ({days} days)
          </h3>
        }
      >
        {trend.initialLoading && <LoadingState label="Loading trend…" />}
        {!trend.initialLoading && trend.error && (
          <ErrorState error={trend.error} onRetry={trend.refetch} />
        )}
        {trend.data && !trend.error && trend.data.trend.length === 0 && (
          <EmptyState
            title="No incident history"
            message="No incidents have been recorded in this window."
          />
        )}
        {trend.data && !trend.error && trend.data.trend.length > 0 && (
          <div style={{ height: 260 }}>
            <ResponsiveContainer width="100%" height="100%">
              <LineChart
                data={trend.data.trend}
                margin={{ top: 5, right: 8, left: -22, bottom: 0 }}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                <XAxis
                  dataKey="date"
                  stroke="#475569"
                  tick={{ fontSize: 9 }}
                  tickFormatter={(v) => String(v).slice(5)}
                />
                <YAxis stroke="#475569" tick={{ fontSize: 9 }} allowDecimals={false} />
                <Tooltip contentStyle={tooltipStyle} />
                <Line
                  type="monotone"
                  dataKey="count"
                  stroke="#06b6d4"
                  strokeWidth={2}
                  dot={{ r: 3, fill: '#06b6d4' }}
                />
              </LineChart>
            </ResponsiveContainer>
          </div>
        )}
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card header={<h3 className="text-sm font-semibold text-white">By Severity</h3>}>
          {bySeverity.error ? (
            <InlineError error={bySeverity.error} />
          ) : severityData.length === 0 ? (
            <EmptyState title="No data" message="" className="py-8" />
          ) : (
            <div style={{ height: 220 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={severityData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={70}
                    label={{ fontSize: 10, fill: '#94a3b8' }}
                  >
                    {severityData.map((entry) => (
                      <Cell
                        key={entry.name}
                        fill={SEVERITY_COLORS[entry.name] || '#64748b'}
                      />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card header={<h3 className="text-sm font-semibold text-white">By Type</h3>}>
          {byType.error ? (
            <InlineError error={byType.error} />
          ) : typeData.length === 0 ? (
            <EmptyState title="No data" message="" className="py-8" />
          ) : (
            <div style={{ height: 220 }}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart
                  data={typeData}
                  layout="vertical"
                  margin={{ top: 5, right: 8, left: 10, bottom: 0 }}
                >
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
                  <XAxis type="number" stroke="#475569" tick={{ fontSize: 9 }} allowDecimals={false} />
                  <YAxis
                    type="category"
                    dataKey="name"
                    stroke="#475569"
                    tick={{ fontSize: 9 }}
                    width={90}
                  />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Bar dataKey="value" fill="#06b6d4" radius={[0, 3, 3, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>

        <Card header={<h3 className="text-sm font-semibold text-white">Assets by Type</h3>}>
          {assetsByType.error ? (
            <InlineError error={assetsByType.error} />
          ) : assetData.length === 0 ? (
            <EmptyState title="No data" message="" className="py-8" />
          ) : (
            <div style={{ height: 220 }}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={assetData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    outerRadius={70}
                    label={{ fontSize: 10, fill: '#94a3b8' }}
                  >
                    {assetData.map((entry, idx) => (
                      <Cell
                        key={entry.name}
                        fill={CHART_COLORS[idx % CHART_COLORS.length]}
                      />
                    ))}
                  </Pie>
                  <Tooltip contentStyle={tooltipStyle} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          )}
        </Card>
      </div>

      <Card
        header={
          <div className="flex items-center gap-2 flex-wrap">
            <h3 className="text-sm font-semibold text-white">
              Mean Time to Resolve (30d)
            </h3>
            <span className="text-[10px] text-gray-500 font-mono ml-auto">
              GET /analytics/mttr
            </span>
          </div>
        }
      >
        {mttr.error ? (
          <InlineError error={mttr.error} />
        ) : mttr.initialLoading ? (
          <LoadingState label="Loading MTTR…" />
        ) : mttr.data ? (
          <div className="space-y-3">
            <MetricTile
              label="Overall MTTR"
              value={mttr.data.overall_mttr_hours?.toFixed(2)}
              suffix="h"
              color="text-accent-cyan"
            />
            {Object.keys(mttr.data.mttr_hours ?? {}).length > 0 && (
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
                {Object.entries(mttr.data.mttr_hours).map(([key, value]) => (
                  <div key={key} className="px-3 py-2 rounded-lg bg-surface/40">
                    <p className="text-[9px] text-gray-500 uppercase tracking-wider">
                      {key}
                    </p>
                    <p className="text-sm font-bold font-mono text-white">
                      {value.toFixed(1)}h
                    </p>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : null}
      </Card>
    </div>
  );
}

/* -------------------------------------------------------------------------- */

export default function AnalyticsPage() {
  return (
    <DashboardLayout>
      <div className="space-y-8">
        <div>
          <h1 className="text-xl font-bold text-white">Analytics &amp; Evaluation</h1>
          <p className="text-xs text-gray-500 mt-1">
            Measured system performance and operational trends.
          </p>
        </div>

        <EvaluationSection />

        <div className="border-t border-surface-border pt-8">
          <OperationalAnalytics />
        </div>
      </div>
    </DashboardLayout>
  );
}
