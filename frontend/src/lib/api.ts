/**
 * Overlook API client.
 *
 * Aligned with API_CONTRACT.md (v1). All routes are mounted under /api/v1.
 *
 * IMPORTANT — implementation status. The contract declares 16 route groups but
 * the backend currently mounts only 7 (see backend/app/api/__init__.py):
 *
 *   LIVE      auth, health, agents, incidents, digital-twin, threat-intel, analytics
 *   NOT BUILT world-model, ingest, forecast, decision, mission, deception,
 *             audit, evaluation, scenario
 *
 * The "not built" methods below are written against the contract so the UI is
 * ready the moment the routers land. Until then they return HTTP 404 and the
 * client surfaces that as `ApiError.notImplemented`, which every page renders
 * as an explicit "endpoint not implemented" state. Nothing is faked or
 * back-filled with placeholder numbers.
 */

const API_BASE =
  process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000/api/v1';

/** Error carrying enough context for the UI to distinguish failure modes. */
export class ApiError extends Error {
  readonly status: number;
  readonly endpoint: string;
  /** True when the backend is unreachable (network/CORS), not an HTTP error. */
  readonly offline: boolean;

  constructor(message: string, status: number, endpoint: string, offline = false) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.endpoint = endpoint;
    this.offline = offline;
  }

  /** A 404 here means the route group has not been implemented yet. */
  get notImplemented(): boolean {
    return this.status === 404;
  }
}

function qs(params?: Record<string, string | number | boolean | undefined>): string {
  if (!params) return '';
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      search.append(key, String(value));
    }
  }
  const out = search.toString();
  return out ? `?${out}` : '';
}

/* -------------------------------------------------------------------------- */
/* Shared / primitive types                                                    */
/* -------------------------------------------------------------------------- */

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type Criticality = 'critical' | 'high' | 'medium' | 'low';

/* -------------------------------------------------------------------------- */
/* World Model  (contract §World Model — NOT YET IMPLEMENTED server-side)      */
/* -------------------------------------------------------------------------- */

export interface Evidence {
  id: string;
  entity_id: string;
  source: string;
  description: string;
  technique_id: string | null;
  likelihood_ratio: number;
  log_likelihood: number;
  severity: Severity;
  timestamp: string;
  age_hours: number;
  decay_weight: number;
  derived: boolean;
  origin_entity: string | null;
  propagation_depth: number;
  propagation_path: string[];
  raw: Record<string, unknown>;
}

/** Mirrors backend/app/world_model/entity_state.py::EntityState.to_dict(). */
export interface EntityState {
  id: string;
  name: string;
  entity_type: string;
  criticality: Criticality;
  p_compromised: number;
  confidence: number;
  state: 'healthy' | 'suspicious' | 'likely_compromised' | 'compromised';
  mission_functions: string[];
  last_updated: string;
  attributes: Record<string, unknown>;
  tags: string[];
  is_deception: boolean;
  isolated: boolean;
  evidence_count: number;
  independent_evidence_count: number;
  evidence: Evidence[];
}

export interface EntityDetail extends EntityState {
  neighbors: string[];
}

export interface WorldModelState {
  snapshot_id: string;
  timestamp: string;
  entity_count: number;
  relation_count: number;
  global_risk: number;
  compromised_count: number;
  entities: EntityState[];
}

export interface WorldModelGraphNode {
  id: string;
  label: string;
  type: string;
  p_compromised: number;
  confidence: number;
  criticality: Criticality;
}

export interface WorldModelGraphEdge {
  source: string;
  target: string;
  type: string;
}

export interface WorldModelGraph {
  nodes: WorldModelGraphNode[];
  edges: WorldModelGraphEdge[];
}

export interface LikelyNextMove {
  technique_id: string;
  name: string;
  tactic: string;
  probability: number;
  eta_minutes: number;
  rationale: string;
}

export interface Capability {
  capability: string;
  demonstrated_by: string[];
  strength: number;
}

export interface AttackerBelief {
  current_objective: string;
  objective_confidence: number;
  inferred_knowledge: string[];
  capabilities: Capability[];
  sophistication: string;
  risk_appetite: string;
  persistence: string;
  campaign_match: { actor: string; confidence: number };
  current_tactic: string;
  observed_techniques: string[];
  likely_next: LikelyNextMove[];
}

export interface UncertainEntity {
  entity_id: string;
  p_compromised: number;
  confidence: number;
  missing_evidence: string[];
  recommended_collection: string[];
}

export interface DefenderBelief {
  overall_confidence: number;
  uncertain_entities: UncertainEntity[];
  coverage_gaps: string[];
  blind_spots: string[];
}

/* -------------------------------------------------------------------------- */
/* Ingest                                                                      */
/* -------------------------------------------------------------------------- */

export interface IngestResult {
  event_id: string;
  normalized: Record<string, unknown>;
  anomaly: Record<string, unknown>;
  mitre: Record<string, unknown>;
  updated_entities: string[];
  world_model_delta: Record<string, unknown>;
}

export interface IngestStatus {
  events_ingested: number;
  last_event_at: string | null;
  sources: Record<string, number>;
}

/* -------------------------------------------------------------------------- */
/* Forecast                                                                    */
/* -------------------------------------------------------------------------- */

export interface ForecastPathStep {
  technique_id: string;
  name: string;
  tactic: string;
  target_entity: string;
  eta_minutes: number;
}

export interface Future {
  id: string;
  name: string;
  probability: number;
  path: ForecastPathStep[];
  terminal_objective: string;
  mission_impact: number;
  confidence: number;
}

export interface ForecastFutures {
  generated_at: string;
  futures: Future[];
}

export interface Intervention {
  type: string;
  target: string;
  params?: Record<string, unknown>;
}

export interface CounterfactualPerFuture {
  future_id: string;
  name: string;
  baseline_probability: number;
  counterfactual_probability: number;
  delta: number;
}

export interface CounterfactualResult {
  baseline_attack_success: number;
  counterfactual_attack_success: number;
  delta: number;
  per_future: CounterfactualPerFuture[];
  mission_impact_delta: number;
  explanation: string;
}

/* -------------------------------------------------------------------------- */
/* Decision                                                                    */
/* -------------------------------------------------------------------------- */

export interface DecisionOption {
  id: string;
  action: string;
  description: string;
  attack_success_after: number;
  attack_success_reduction: number;
  mission_impact: number;
  recovery_cost: number;
  blast_radius: number;
  risk_level: string;
  approval_required: boolean;
  reversible: boolean;
  rollback: string;
  rationale: string;
  evidence: string[];
  score: number;
}

export interface DecisionOptions {
  options: DecisionOption[];
  recommended_id: string;
}

export interface ExecutionStep {
  step: string;
  status: string;
  detail?: string;
}

export interface ExecutionResult {
  execution_id: string;
  status: 'executed' | 'pending_approval';
  steps: ExecutionStep[];
  audit_id: string;
}

export interface PendingApproval {
  execution_id: string;
  option_id: string;
  action: string;
  description: string;
  requested_at: string;
  requested_by: string;
  risk_level: string;
  mission_impact: number;
  attack_success_reduction: number;
  rationale: string;
}

/* -------------------------------------------------------------------------- */
/* Mission                                                                     */
/* -------------------------------------------------------------------------- */

export interface MissionFunction {
  name: string;
  availability: number;
  dependent_entities: string[];
  degradation: number;
  population_affected: number;
  safety_risk: string;
}

export interface MissionImpact {
  functions: MissionFunction[];
  overall_mission_risk: number;
}

/* -------------------------------------------------------------------------- */
/* Deception                                                                   */
/* -------------------------------------------------------------------------- */

export interface DeceptionAsset {
  id: string;
  asset_type: string;
  near_entity: string;
  deployed_at: string;
  triggered: boolean;
  interactions: number;
}

/* -------------------------------------------------------------------------- */
/* Audit                                                                       */
/* -------------------------------------------------------------------------- */

export interface AuditEntry {
  id: string;
  timestamp: string;
  actor: string;
  actor_type: string;
  action: string;
  target: string;
  decision: string;
  confidence: number;
  evidence: string[];
  reasoning: string;
  alternatives: string[];
  approved_by: string | null;
  rollback_available: boolean;
  outcome: string;
}

/* -------------------------------------------------------------------------- */
/* Evaluation — the judged metrics                                             */
/* -------------------------------------------------------------------------- */

export interface DetectionEval {
  dataset: string;
  samples: number;
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  f1: number;
  fpr: number;
  roc_auc: number;
}

export interface AttributionPerTechnique {
  technique_id: string;
  name: string;
  correct: number;
  total: number;
  accuracy: number;
}

export interface AttributionEval {
  technique_accuracy: number;
  tactic_accuracy: number;
  per_technique: AttributionPerTechnique[];
}

export interface ResponseCoveragePlaybook {
  playbook: string;
  total_steps: number;
  automatable: number;
  coverage_pct: number;
}

export interface ResponseCoverageEval {
  total_steps: number;
  automatable: number;
  coverage_pct: number;
  per_playbook: ResponseCoveragePlaybook[];
}

export interface MttdMttrEval {
  baseline_mttd_minutes: number;
  sentinel_mttd_minutes: number;
  mttd_improvement_pct: number;
  baseline_mttr_minutes: number;
  sentinel_mttr_minutes: number;
  mttr_improvement_pct: number;
}

/* -------------------------------------------------------------------------- */
/* Scenario                                                                    */
/* -------------------------------------------------------------------------- */

export interface Scenario {
  id: string;
  name: string;
  description: string;
  actor?: string;
  steps?: number;
  duration_minutes?: number;
}

export interface ScenarioStatus {
  running: boolean;
  scenario_id: string | null;
  scenario_name?: string | null;
  current_step: number;
  total_steps: number;
  started_at: string | null;
  events_injected: number;
}

/* -------------------------------------------------------------------------- */
/* Pre-existing routers — shapes verified against the backend source           */
/* -------------------------------------------------------------------------- */

export type AgentStatus = 'idle' | 'running' | 'error' | 'disabled';
export type AgentType =
  | 'monitor'
  | 'analyzer'
  | 'responder'
  | 'orchestrator'
  | 'threat_intel'
  | 'digital_twin'
  | 'compliance'
  | 'forensic';

export interface Agent {
  id: string;
  name: string;
  agent_type: AgentType;
  status: AgentStatus;
  description: string | null;
  config: Record<string, unknown>;
  tags: string[];
  last_heartbeat: string | null;
  created_at: string;
  updated_at: string;
}

export interface AgentActionResponse {
  agent_id: string;
  action: string;
  status: string;
  result: unknown | null;
  error: string | null;
  execution_time_ms: number | null;
  timestamp: string;
}

export type IncidentStatus =
  | 'new'
  | 'investigating'
  | 'contained'
  | 'remediated'
  | 'resolved'
  | 'closed'
  | 'false_positive';
export type IncidentPriority = 'p0' | 'p1' | 'p2' | 'p3' | 'p4';
export type IncidentType =
  | 'malware'
  | 'phishing'
  | 'ransomware'
  | 'data_breach'
  | 'dos'
  | 'insider_threat'
  | 'unauthorized_access'
  | 'policy_violation'
  | 'network_intrusion'
  | 'other';

export interface IncidentSummary {
  id: string;
  title: string;
  status: IncidentStatus;
  severity: Criticality;
  priority: IncidentPriority;
  incident_type: IncidentType;
  created_at: string;
  assigned_to: string | null;
  age_hours: number | null;
}

export interface Incident {
  id: string;
  title: string;
  description: string;
  incident_type: IncidentType;
  status: IncidentStatus;
  severity: Criticality;
  priority: IncidentPriority;
  source: string | null;
  affected_assets: string[];
  mitre_techniques: string[];
  indicators: string[];
  assigned_to: string | null;
  tags: string[];
  resolution_notes: string | null;
  created_by: string | null;
  created_at: string;
  updated_at: string;
  resolved_at: string | null;
}

export interface IncidentTimelineEntry {
  incident_id: string;
  action: string;
  actor: string;
  description: string;
  metadata: Record<string, unknown> | null;
  timestamp: string;
}

export interface IncidentStats {
  total: number;
  last_24h: number;
  by_status: Record<string, number>;
  by_severity: Record<string, number>;
  by_type: Record<string, number>;
}

export type AssetType =
  | 'server'
  | 'workstation'
  | 'network_device'
  | 'database'
  | 'application'
  | 'cloud_instance'
  | 'container'
  | 'iot_device'
  | 'security_appliance'
  | 'storage'
  | 'virtual_machine'
  | 'other';

export interface Asset {
  id: string;
  name: string;
  asset_type: AssetType;
  ip_address: string | null;
  hostname: string | null;
  domain: string | null;
  os: string | null;
  os_version: string | null;
  criticality: Criticality;
  location: string | null;
  department: string | null;
  owner: string | null;
  tags: string[];
  metadata: Record<string, unknown>;
  created_at: string;
  updated_at: string;
}

export interface AssetRelationship {
  id: string;
  source_asset_id: string;
  target_asset_id: string;
  relationship_type: string;
  label: string | null;
  metadata: Record<string, unknown>;
  created_at: string;
}

/** Note: the backend returns `relationships`, not the contract's `edges`. */
export interface AssetGraph {
  nodes: Asset[];
  relationships: AssetRelationship[];
}

export interface DigitalTwinAssetState {
  asset_id: string;
  current_status: string;
  cpu_usage: number | null;
  memory_usage: number | null;
  disk_usage: number | null;
  network_in: number | null;
  network_out: number | null;
  running_processes: string[] | null;
  open_ports: number[] | null;
  vulnerabilities: Record<string, unknown>[] | null;
  last_updated: string;
}

export interface SimulationResult {
  simulation_id: string;
  asset_id: string;
  scenario: string;
  status: string;
  impact_analysis: Record<string, unknown>;
  risk_score: number | null;
  recommendations: string[];
  started_at: string;
  completed_at: string;
}

export type EventCategory =
  | 'anomaly'
  | 'threat'
  | 'compliance'
  | 'system'
  | 'network'
  | 'application'
  | 'infrastructure'
  | 'user';

export interface ThreatEvent {
  id: string;
  event_type: string;
  category: EventCategory;
  severity: Severity;
  source: string;
  title: string;
  description: string;
  raw_data: Record<string, unknown> | null;
  metadata: Record<string, unknown> | null;
  tags: string[];
  correlation_id: string | null;
  processed: boolean;
  timestamp: string;
  created_at: string;
}

export interface MitreTechnique {
  id?: string;
  technique_id?: string;
  name?: string;
  tactic?: string;
  tactics?: string[];
  description?: string;
  [key: string]: unknown;
}

export interface MitreTactic {
  id?: string;
  tactic_id?: string;
  name?: string;
  short_name?: string;
  description?: string;
  [key: string]: unknown;
}

export interface AnalyticsDashboard {
  incidents: { total: number; open: number; critical: number; last_24h: number };
  assets: { total: number; critical: number };
  agents: { total: number; active: number };
  events_last_24h: number;
  timestamp: string;
}

export interface IncidentTrend {
  days: number;
  trend: { date: string; count: number }[];
}

export interface MttrAnalytics {
  days: number;
  mttr_hours: Record<string, number>;
  overall_mttr_hours: number;
}

export interface ServiceStatus {
  status: 'healthy' | 'unhealthy' | 'unknown';
  error?: string;
}

export interface HealthResponse {
  status: 'healthy' | 'degraded';
  version: string;
  name: string;
  services: Record<string, ServiceStatus>;
}

/* -------------------------------------------------------------------------- */
/* Client                                                                      */
/* -------------------------------------------------------------------------- */

class ApiClient {
  private token: string | null = null;

  setToken(token: string) {
    this.token = token;
  }

  private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...(options.headers as Record<string, string>),
    };
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;

    let response: Response;
    try {
      response = await fetch(`${API_BASE}${endpoint}`, { ...options, headers });
    } catch (cause) {
      throw new ApiError(
        `Cannot reach the Overlook backend at ${API_BASE}`,
        0,
        endpoint,
        true
      );
    }

    if (!response.ok) {
      let detail = response.statusText;
      try {
        const body = await response.json();
        if (body?.detail) detail = String(body.detail);
      } catch {
        /* response had no JSON body — keep the status text */
      }
      throw new ApiError(detail, response.status, endpoint);
    }

    if (response.status === 204) return undefined as T;
    return response.json();
  }

  /* ---- Auth ---- */

  login = (username: string, password: string) =>
    this.request<{ access_token: string; token_type: string; expires_in: number }>(
      '/auth/login',
      { method: 'POST', body: JSON.stringify({ username, password }) }
    );

  /* ---- Health ---- */

  getHealth = () => this.request<HealthResponse>('/health');

  /* ---- World Model ---- */

  getWorldModelState = () => this.request<WorldModelState>('/world-model/state');

  getEntities = (params?: { entity_type?: string; min_compromise?: number }) =>
    this.request<EntityState[]>(`/world-model/entities${qs(params)}`);

  getEntity = (id: string) =>
    this.request<EntityDetail>(`/world-model/entities/${encodeURIComponent(id)}`);

  getWorldModelGraph = () => this.request<WorldModelGraph>('/world-model/graph');

  getAttackerBelief = () =>
    this.request<AttackerBelief>('/world-model/attacker-belief');

  getDefenderBelief = () =>
    this.request<DefenderBelief>('/world-model/defender-belief');

  resetWorldModel = () =>
    this.request<{ status: string }>('/world-model/reset', { method: 'POST' });

  /* ---- Ingest ---- */

  ingestEvent = (event: Record<string, unknown>) =>
    this.request<IngestResult>('/ingest/event', {
      method: 'POST',
      body: JSON.stringify(event),
    });

  ingestBatch = (events: Record<string, unknown>[]) =>
    this.request<{ ingested: number; updated_entities: string[] }>('/ingest/batch', {
      method: 'POST',
      body: JSON.stringify({ events }),
    });

  getIngestStatus = () => this.request<IngestStatus>('/ingest/status');

  /* ---- Forecast ---- */

  getFutures = (horizonMinutes = 60) =>
    this.request<ForecastFutures>(
      `/forecast/futures${qs({ horizon_minutes: horizonMinutes })}`
    );

  runCounterfactual = (interventions: Intervention[]) =>
    this.request<CounterfactualResult>('/forecast/counterfactual', {
      method: 'POST',
      body: JSON.stringify({ interventions }),
    });

  /* ---- Decision ---- */

  getDecisionOptions = () => this.request<DecisionOptions>('/decision/options');

  executeDecision = (optionId: string, approvedBy: string) =>
    this.request<ExecutionResult>('/decision/execute', {
      method: 'POST',
      body: JSON.stringify({ option_id: optionId, approved_by: approvedBy }),
    });

  getPendingApprovals = () =>
    this.request<PendingApproval[]>('/decision/pending-approvals');

  approveExecution = (
    executionId: string,
    approvedBy: string,
    decision: 'approve' | 'reject',
    reason: string
  ) =>
    this.request<{ status: string; execution_id: string }>(
      `/decision/approve/${encodeURIComponent(executionId)}`,
      {
        method: 'POST',
        body: JSON.stringify({ approved_by: approvedBy, decision, reason }),
      }
    );

  rollbackExecution = (executionId: string) =>
    this.request<{ status: string; execution_id: string }>(
      `/decision/rollback/${encodeURIComponent(executionId)}`,
      { method: 'POST' }
    );

  /* ---- Mission ---- */

  getMissionImpact = () => this.request<MissionImpact>('/mission/impact');

  /* ---- Deception ---- */

  getDeceptionAssets = () => this.request<DeceptionAsset[]>('/deception/assets');

  deployDeception = (assetType: string, nearEntity: string) =>
    this.request<DeceptionAsset>('/deception/deploy', {
      method: 'POST',
      body: JSON.stringify({ asset_type: assetType, near_entity: nearEntity }),
    });

  /* ---- Audit ---- */

  getAuditTrail = (params?: { limit?: number; actor?: string; action?: string }) =>
    this.request<AuditEntry[]>(`/audit/trail${qs(params)}`);

  getAuditEntry = (id: string) =>
    this.request<AuditEntry>(`/audit/trail/${encodeURIComponent(id)}`);

  /* ---- Evaluation ---- */

  getDetectionEval = () => this.request<DetectionEval>('/evaluation/detection');

  getAttributionEval = () => this.request<AttributionEval>('/evaluation/attribution');

  getResponseCoverage = () =>
    this.request<ResponseCoverageEval>('/evaluation/response-coverage');

  getMttdMttr = () => this.request<MttdMttrEval>('/evaluation/mttd-mttr');

  runEvaluation = () =>
    this.request<{ status: string }>('/evaluation/run', { method: 'POST' });

  /* ---- Scenario ---- */

  listScenarios = () => this.request<Scenario[]>('/scenario/list');

  runScenario = (scenarioId: string, speed = 1) =>
    this.request<{ status: string; scenario_id: string }>('/scenario/run', {
      method: 'POST',
      body: JSON.stringify({ scenario_id: scenarioId, speed }),
    });

  getScenarioStatus = () => this.request<ScenarioStatus>('/scenario/status');

  /* ---- Agents ---- */

  getAgents = (params?: { status?: string; agent_type?: string; search?: string }) =>
    this.request<Agent[]>(`/agents${qs(params)}`);

  getAgent = (id: string) => this.request<Agent>(`/agents/${encodeURIComponent(id)}`);

  updateAgent = (id: string, patch: Partial<Pick<Agent, 'name' | 'description' | 'status' | 'tags'>>) =>
    this.request<Agent>(`/agents/${encodeURIComponent(id)}`, {
      method: 'PUT',
      body: JSON.stringify(patch),
    });

  /** Replaces the old `/agents/{type}/dispatch`, which never existed. */
  runAgentAction = (agentId: string, action: string, params?: Record<string, unknown>) =>
    this.request<AgentActionResponse>(
      `/agents/${encodeURIComponent(agentId)}/action`,
      {
        method: 'POST',
        body: JSON.stringify({ agent_id: agentId, action, params: params ?? {} }),
      }
    );

  /* ---- Incidents ---- */

  getIncidents = (params?: {
    status?: string;
    severity?: string;
    incident_type?: string;
    search?: string;
    page?: number;
    page_size?: number;
  }) => this.request<IncidentSummary[]>(`/incidents${qs(params)}`);

  getIncident = (id: string) =>
    this.request<Incident>(`/incidents/${encodeURIComponent(id)}`);

  getIncidentTimeline = (id: string) =>
    this.request<IncidentTimelineEntry[]>(
      `/incidents/${encodeURIComponent(id)}/timeline`
    );

  getIncidentStats = () => this.request<IncidentStats>('/incidents/stats/overview');

  /* ---- Digital Twin / Assets ---- */

  getAssets = (params?: { asset_type?: string; criticality?: string; search?: string }) =>
    this.request<Asset[]>(`/digital-twin/assets${qs(params)}`);

  getAsset = (id: string) =>
    this.request<Asset>(`/digital-twin/assets/${encodeURIComponent(id)}`);

  getTwinGraph = (params?: { asset_id?: string; depth?: number }) =>
    this.request<AssetGraph>(`/digital-twin/graph${qs(params)}`);

  getAssetState = (id: string) =>
    this.request<DigitalTwinAssetState>(
      `/digital-twin/assets/${encodeURIComponent(id)}/state`
    );

  runSimulation = (payload: {
    asset_id: string;
    scenario: string;
    parameters?: Record<string, unknown>;
    duration_seconds?: number;
  }) =>
    this.request<SimulationResult>('/digital-twin/simulate', {
      method: 'POST',
      body: JSON.stringify({
        parameters: {},
        duration_seconds: 60,
        ...payload,
      }),
    });

  /* ---- Threat Intel ---- */

  getIndicators = (params?: {
    indicator_type?: string;
    severity?: string;
    search?: string;
    page_size?: number;
  }) => this.request<ThreatEvent[]>(`/threat-intel/indicators${qs(params)}`);

  /** Replaces the old `/threat-intel/mitre`, which never existed. */
  getMitreTechniques = (params?: { search?: string; tactic?: string }) =>
    this.request<MitreTechnique[]>(`/threat-intel/mitre/techniques${qs(params)}`);

  getMitreTactics = () => this.request<MitreTactic[]>('/threat-intel/mitre/tactics');

  getThreatIntelStats = () =>
    this.request<{
      total_events: number;
      by_severity: Record<string, number>;
      by_category: Record<string, number>;
      by_source: Record<string, number>;
      time_range_hours: number;
    }>('/threat-intel/stats');

  /* ---- Analytics ---- */

  getDashboard = () => this.request<AnalyticsDashboard>('/analytics/dashboard');

  /** Contract path is `/analytics/incidents/trend` (not `/analytics/trends`). */
  getIncidentTrend = (days = 7) =>
    this.request<IncidentTrend>(`/analytics/incidents/trend${qs({ days })}`);

  getIncidentsBySeverity = () =>
    this.request<Record<string, number>>('/analytics/incidents/by-severity');

  getIncidentsByType = () =>
    this.request<Record<string, number>>('/analytics/incidents/by-type');

  getAssetsByType = () =>
    this.request<Record<string, number>>('/analytics/assets/by-type');

  getAssetsByCriticality = () =>
    this.request<Record<string, number>>('/analytics/assets/by-criticality');

  getAgentsByStatus = () =>
    this.request<Record<string, number>>('/analytics/agents/by-status');

  getMttr = (days = 30) => this.request<MttrAnalytics>(`/analytics/mttr${qs({ days })}`);
}

export const api = new ApiClient();
export { API_BASE };
