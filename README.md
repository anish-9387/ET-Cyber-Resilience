# Sentinel - Cyber World Model for Critical National Infrastructure

Sentinel maintains a **living probabilistic model** of an organisation's cyber
environment. Rather than asking "did an attack happen?", it asks what the
environment currently looks like, what the attacker is probably trying to
achieve, which futures are most likely, and which defensive action produces the
safest one.

**Observe → Understand → Build World Model → Reason → Predict → Plan → Respond → Learn**

See [ARCHITECTURE.md](ARCHITECTURE.md) for diagrams and
[API_CONTRACT.md](API_CONTRACT.md) for the full API.

---

## Quick start

Nothing except Python and Node is required. The backend runs on SQLite with
Neo4j, Qdrant, Redis and Ollama all absent.

```bash
# Backend
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --port 8000          # http://localhost:8000/docs

# Frontend (separate terminal)
cd frontend && npm install && npm run dev  # http://localhost:3000
```

Then drive the whole pipeline:

```bash
python scripts/demo_attack_scenario.py --scenario lockbit_hospital
```

This ingests a labelled LockBit chain, updates the world model, infers attacker
intent, forecasts futures, runs a counterfactual, ranks containment options and
prints the audit trail. It has **no fallback values**: if the backend is down or
an endpoint is missing it fails loudly and exits non-zero.

---

## What is actually measured

**Do not trust performance claims in a README - including this one.** Run the
harness and read the numbers it prints:

```bash
cd backend && python -m app.evaluation.runner
```

It computes, at run time and from code:

| Criterion | Where |
|---|---|
| Detection rate / false-positive rate, ROC-AUC, threshold sweep | `app/evaluation/detection_eval.py` |
| MITRE attribution accuracy at technique and tactic level | `app/evaluation/attribution_eval.py` |
| Response automation coverage | `app/evaluation/response_eval.py` |
| MTTD / MTTR vs an external baseline | `app/evaluation/timing_eval.py` |

Also exposed at `/api/v1/evaluation/*` and rendered on `/analytics`.

An earlier version of this file claimed "82% prediction accuracy", "90% false
positive reduction" and "MTTR reduced from hours to seconds". **No code computed
any of those numbers.** They have been removed rather than restated. The
evaluation package exists so that every such claim is reproducible or absent.

### Known limits, stated up front

- **The benchmark corpus is synthetic.** Deterministic under a fixed seed, built
  from the bundled scenarios. It is not real-world performance. An adapter for
  CICIDS2017 / UNSW-NB15 / BETH is documented in `app/evaluation/datasets.py`.
- **Response execution is simulated.** `SimulatedExecutor` renders and records
  commands; there is no firewall, AD, EDR or hypervisor integration. Every
  payload carries `mode: "simulated"`, `integration: "none"`, `enforced: false`.
  Automation coverage reports `steps_automatable_by_policy` separately from
  `steps_with_real_integration` (which is zero).
- **MITRE coverage is partial** - 49 of ~625 Enterprise techniques and no
  sub-techniques. The attribution report states this ceiling explicitly.
- **The MTTD/MTTR baseline is an external industry reference**, not a SOC
  measured here, and is not a like-for-like comparison.
- **CERT-In ingestion is a stub.** MITRE CTI, CISA KEV and NVD fetchers are real.
- The audit trail is in-memory and does not survive a restart.

---

## Capabilities

| | |
|---|---|
| **Probabilistic world model** | Per-entity `P(compromised)` with confidence, updated by Bayesian evidence fusion in log-odds space, with recency decay and direction-aware neighbour propagation |
| **Attacker belief** | Objective inference, inferred attacker knowledge, campaign attribution by technique-set Jaccard similarity |
| **Defender belief** | Models Sentinel's *own* uncertainty - which beliefs are weak, what evidence is missing, what to collect next |
| **Attack forecast** | Deterministic probability-tree expansion into multiple ranked futures with target entities and ETAs |
| **Counterfactual** | Applies interventions to a model clone, re-forecasts, reports which attack paths were severed |
| **Mission impact** | Availability of patient care, emergency response, diagnostics, records, power and water as dependent-entity beliefs shift |
| **Decision engine** | Ranks real playbooks by attack-success reduction against mission impact and recovery cost, with alternatives recorded |
| **Human-in-the-loop** | Gated actions cannot self-approve. Approval requires an authenticated principal holding an approver role |
| **Audit trail** | Append-only record of every belief update and automated decision, with evidence, reasoning, alternatives considered, approver and rollback handle |

## Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 16 (Turbopack), React 19, TypeScript, Tailwind, React Flow, Three.js, Recharts |
| Backend | FastAPI, Python 3.11+ |
| Relational | SQLite (default) or PostgreSQL |
| ML | scikit-learn (IsolationForest), NumPy, NetworkX |
| Optional | Neo4j, Qdrant, Redis, Ollama, sentence-transformers |
| Threat intel | MITRE ATT&CK, CISA KEV, NVD |
| Telemetry formats | Windows/Sysmon, Linux, syslog, auditd, Zeek, Suricata, Wazuh, firewall, CloudTrail |

Kafka, LangGraph and CrewAI were previously listed here. None are used -
orchestration is a hand-rolled coordinator and the event bus is in-process with
optional Redis pub/sub.

---

## Scenarios

| ID | Chain |
|---|---|
| `lockbit_hospital` | Phishing → credential dumping → lateral movement → backup destruction → encryption |
| `apt29_espionage` | Slow espionage over days ending in cloud exfiltration |
| `ot_water_scada` | OT/SCADA intrusion ending in a chlorine-dosing safety event |

Each event carries ground-truth `is_malicious` and `true_technique` labels, which
is what makes the evaluation harness possible.

```bash
curl -X POST localhost:8000/api/v1/scenario/run \
  -H 'Content-Type: application/json' \
  -d '{"scenario_id":"lockbit_hospital","speed":20}'
```

## Tests

```bash
cd backend && python -m pytest -q
```

## Layout

```
backend/app/
  world_model/   entity state, Bayesian fusion, attacker/defender belief,
                 forecast, counterfactual, mission impact, decision engine, audit
  agents/        behaviour, MITRE mapper, prediction, response, playbooks, ...
  ml/            IsolationForest detector, sequence model, structural embedder
  services/      telemetry normalizers, threat intel, analytics, notifications
  evaluation/    labelled corpus + detection/attribution/response/timing harnesses
  scenarios/     labelled APT chains
frontend/src/app/  14 routes
```
