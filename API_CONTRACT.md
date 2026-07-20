# Sentinel API Contract (v1)

All routes are mounted under `/api/v1`. This file is the single source of truth
shared by the backend routers and the frontend client (`frontend/src/lib/api.ts`).

## Core singleton

```python
from app.world_model import world_model, Observation

obs = Observation(
    entity_id: str,
    source: str,                 # "sysmon" | "zeek" | "windows" | "firewall" | ...
    description: str,
    technique_id: str | None,    # MITRE technique, e.g. "T1021.002"
    likelihood_ratio: float,     # >1 raises P(compromised), <1 lowers it
    severity: str,               # critical|high|medium|low|info
    timestamp: datetime,
    raw: dict,
)

await world_model.ingest_observation(obs) -> list[str]   # updated entity ids
world_model.get_entity(entity_id) -> EntityState | None
world_model.all_entities() -> list[EntityState]
world_model.snapshot() -> dict
world_model.graph() -> dict
world_model.attacker_belief() -> dict
world_model.defender_belief() -> dict
world_model.load_seed(seed: dict) -> None
world_model.reset() -> None
```

`EntityState` fields: `id, name, entity_type, criticality, p_compromised,
confidence, state, evidence[], mission_functions[], last_updated`.

## Routes

### World Model
- `GET  /world-model/state` -> `{snapshot_id, timestamp, entity_count, relation_count, global_risk, compromised_count, entities[]}`
- `GET  /world-model/entities?entity_type=&min_compromise=` -> `[EntityState]`
- `GET  /world-model/entities/{id}` -> `EntityState + {evidence[], neighbors[]}`
- `GET  /world-model/graph` -> `{nodes:[{id,label,type,p_compromised,confidence,criticality}], edges:[{source,target,type}]}`
- `GET  /world-model/attacker-belief` -> `{current_objective, objective_confidence, inferred_knowledge[], capabilities[], sophistication, risk_appetite, persistence, campaign_match:{actor,confidence}, current_tactic, observed_techniques[], likely_next:[{technique_id,name,tactic,probability,eta_minutes,rationale}]}`
- `GET  /world-model/defender-belief` -> `{overall_confidence, uncertain_entities:[{entity_id,p_compromised,confidence,missing_evidence[],recommended_collection[]}], coverage_gaps[], blind_spots[]}`
- `POST /world-model/reset`

### Ingest
- `POST /ingest/event` body = raw telemetry `{source_type, ...}` -> `{event_id, normalized, anomaly, mitre, updated_entities[], world_model_delta}`
- `POST /ingest/batch` body `{events:[...]}` -> summary
- `GET  /ingest/status`

### Forecast
- `GET  /forecast/futures?horizon_minutes=60` -> `{generated_at, futures:[{id,name,probability,path:[{technique_id,name,tactic,target_entity,eta_minutes}],terminal_objective,mission_impact,confidence}]}`
- `POST /forecast/counterfactual` body `{interventions:[{type,target,params}]}` -> `{baseline_attack_success, counterfactual_attack_success, delta, per_future[], mission_impact_delta, explanation}`

### Decision
- `GET  /decision/options` -> `{options:[{id,action,description,attack_success_after,attack_success_reduction,mission_impact,recovery_cost,blast_radius,risk_level,approval_required,reversible,rollback,rationale,evidence[],score}], recommended_id}`
- `POST /decision/execute` body `{option_id, approved_by}` -> `{execution_id, status: executed|pending_approval, steps[], audit_id}`
- `GET  /decision/pending-approvals`
- `POST /decision/approve/{execution_id}` body `{approved_by, decision: approve|reject, reason}`
- `POST /decision/rollback/{execution_id}`

### Mission
- `GET  /mission/impact` -> `{functions:[{name,availability,dependent_entities,degradation,population_affected,safety_risk}], overall_mission_risk}`

### Deception
- `GET  /deception/assets`
- `POST /deception/deploy` body `{asset_type, near_entity}`

### Audit
- `GET  /audit/trail?limit=&actor=&action=` -> `[{id,timestamp,actor,actor_type,action,target,decision,confidence,evidence[],reasoning,alternatives[],approved_by,rollback_available,outcome}]`
- `GET  /audit/trail/{id}`

### Evaluation
- `GET  /evaluation/detection` -> `{dataset,samples,tp,fp,tn,fn,precision,recall,f1,fpr,roc_auc}`
- `GET  /evaluation/attribution` -> `{technique_accuracy,tactic_accuracy,per_technique[]}`
- `GET  /evaluation/response-coverage` -> `{total_steps,automatable,coverage_pct,per_playbook[]}`
- `GET  /evaluation/mttd-mttr` -> `{baseline_mttd_minutes,sentinel_mttd_minutes,mttd_improvement_pct,baseline_mttr_minutes,sentinel_mttr_minutes,mttr_improvement_pct}`
- `POST /evaluation/run`

### Scenario
- `GET  /scenario/list`
- `POST /scenario/run` body `{scenario_id, speed}` -> injects an APT chain into the world model
- `GET  /scenario/status`

### Pre-existing (unchanged)
`/auth/*`, `/incidents/*`, `/assets` + `/digital-twin/*`, `/threat-intel/*`,
`/analytics/*`, `/agents/*`, `/health/*`
