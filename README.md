# Overlook

**Cyber World Model for Critical National Infrastructure**

Overlook maintains a living probabilistic model of an organisation's cyber environment. Rather than asking "did an attack happen?", it asks what the environment currently looks like, what the attacker is probably trying to achieve, which futures are most likely, and which defensive action produces the safest one.

```
Observe → Understand → Build World Model → Reason → Predict → Plan → Respond → Learn
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                        Frontend (Next.js 14)                     │
│  Dashboard │ World Model │ Forecast │ Decision │ Incidents │ ... │
└──────────────────────────┬───────────────────────────────────────┘
                           │ HTTP (REST)
┌──────────────────────────▼───────────────────────────────────────┐
│                     Backend (FastAPI / Python 3.12)              │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────────┐  │
│  │ World    │ │ Agents   │ │ ML       │ │ Evaluation         │  │
│  │ Model    │ │ (14)     │ │ Detector │ │ Harness            │  │
│  └──────────┘ └──────────┘ └──────────┘ └────────────────────┘  │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌────────────────────┐  │
│  │ API      │ │ Services │ │ Schemas  │ │ Scenarios (3 APT)  │  │
│  └──────────┘ └──────────┘ └──────────┘ └────────────────────┘  │
└──────────────────────────────────────────────────────────────────┘
```

See [ARCHITECTURE.md](ARCHITECTURE.md) for detailed diagrams and [API_CONTRACT.md](API_CONTRACT.md) for the full API reference.

---

## Prerequisites

| Dependency | Version | Notes |
|------------|---------|-------|
| Python | 3.11+ | 3.12 recommended |
| Node.js | 18+ | 20+ recommended |
| pnpm | 8+ | or npm |

---

## Quick Start

### 1. Backend

```bash
cd backend
python -m venv venv

# Windows
venv\Scripts\activate
# Linux/macOS
# source venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

API docs available at http://localhost:8000/docs

The backend starts with an in-memory SQLite database and seeds a realistic world model topology on first launch. Neo4j, Qdrant, Redis, and Ollama are optional - the app runs fully without them.

### 2. Frontend

```bash
cd frontend
pnpm install
pnpm run dev
```

Open http://localhost:3000 in your browser. The frontend proxies `/api/*` requests to the backend automatically (configured in `next.config.js`).

---

## Running a Scenario

Overlook ships with 3 labelled APT attack chains for testing:

| Scenario | Chain |
|----------|-------|
| `lockbit_hospital` | Phishing → credential dumping → lateral movement → backup destruction → encryption |
| `apt29_espionage` | Slow espionage over days ending in cloud exfiltration |
| `ot_water_scada` | OT/SCADA intrusion ending in a chlorine-dosing safety event |

### Via CLI

```bash
python scripts/demo_attack_scenario.py --scenario lockbit_hospital
```

### Via API

```bash
curl -X POST http://localhost:8000/api/v1/scenario/run \
  -H 'Content-Type: application/json' \
  -d '{"scenario_id":"lockbit_hospital","speed":20}'
```

### Via UI

Navigate to the **Scenario** page and click **Run** on any scenario card.

Each scenario ingests telemetry into the world model, updates attacker/defender beliefs, generates forecasts, runs counterfactuals, ranks response options, and records everything in the audit trail.

---

## Training the Model

Overlook has **two independent detection models**, validated on different data.

### 1. Host-Behavioural Detector (IsolationForest)

Trained online at runtime from ingested telemetry. No separate training step is required - the `BehaviourLearningAgent` fits automatically as events arrive.

To retrain from scratch:

```bash
cd backend
python -c "
from app.ml.anomaly_detector import AnomalyDetector
import numpy as np
detector = AnomalyDetector()
detector.fit(np.random.rand(1000, 10))
detector.save('models/anomaly/isolation_forest.pkl')
print('Model saved')
"
```

### 2. Network-Flow Detector (UNSW-NB15)

An offline model trained and validated on the **real public UNSW-NB15 NIDS benchmark**. This is a standalone artifact registered under `backend/models/real/` with full provenance tracking.

```bash
# Activate the backend virtual environment first
cd backend
.\venv\Scripts\activate  # Windows
# source venv/bin/activate  # Linux/macOS

# Train on UNSW-NB15 (auto-downloads ~105 MB from Hugging Face)
python ../scripts/train_anomaly_detector_real.py --dataset unsw
```

**Pipeline:**
1. Downloads UNSW-NB15 training-set CSV to `backend/data/unsw_nb15/`
2. Builds a stratified 70/30 train/test split (seed 42)
3. Fits preprocessing (categorical vocabulary + `StandardScaler`) on training split only
4. Trains **unsupervised IsolationForest** (features only, no labels)
5. Trains **supervised RandomForest** (features + labels)
6. Registers both in `ModelRegistry` with full metadata and persists to `backend/models/real/`
7. Evaluates on the held-out test split and prints a report

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--dataset` | `unsw` | `unsw` or `beth` |
| `--path` | auto-download | Path to local CSV |
| `--test-size` | `0.3` | Test split fraction |
| `--seed` | `42` | RNG seed |
| `--max-rows` | None | Cap rows for quick testing |

**Expected metrics (UNSW-NB15 test split, 52,603 flows, 68% attack):**

| Model | ROC-AUC | Detection @ 1% FPR | @ 5% FPR |
|-------|---------|---------------------|-----------|
| RandomForest (supervised) | 0.994 | 0.880 | 0.958 |
| IsolationForest (unsupervised) | 0.245 | 0.003 | 0.031 |

The IsolationForest result is expected - the UNSW partition is 68% attacks, so an unsupervised novelty detector learns the attack traffic as the "normal" dense region and inverts. This is why the supervised model (or a benign-only fit) is needed.

### 3. Using the BETH Dataset

BETH (Highnam et al. 2021) is a host/kernel behavioural telemetry dataset, closer to Overlook's UEBA framing. It is Kaggle-auth-gated:

```bash
python ../scripts/train_anomaly_detector_real.py --dataset beth --path /path/to/labelled_data.csv
```

### 4. Recalibrating the Likelihood-Ratio Mapping

The anomaly-score → Bayesian likelihood-ratio mapping used in the ingestion pipeline is calibrated from the synthetic benchmark corpus:

```bash
cd backend
python -m app.evaluation.calibration
```

This prints `ANOMALY_LR_INTERCEPT` and `ANOMALY_LR_SLOPE` to paste into `app/api/ingest.py`.

---

## Running the Evaluation Suite

Every metric in Overlook is computed at runtime - nothing is hardcoded.

```bash
cd backend
python -m app.evaluation.runner
```

**Flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `--seed` | `42` | Corpus RNG seed |
| `--benign-count` | `4000` | Benign background records |
| `--scenario-repeats` | `4` | Instantiations of each APT scenario |
| `--external-dataset` | None | Path to CICIDS2017/UNSW-NB15/BETH CSV |
| `--json` | false | Print report as JSON |
| `--output` | None | Write JSON report to file |

The suite evaluates:

| Criterion | Source |
|-----------|--------|
| Detection rate / FPR / ROC-AUC | `app/evaluation/detection_eval.py` |
| MITRE attribution accuracy | `app/evaluation/attribution_eval.py` |
| Response automation coverage | `app/evaluation/response_eval.py` |
| MTTD / MTTR vs baseline | `app/evaluation/timing_eval.py` |

Results are also available via `GET /api/v1/evaluation/*` and rendered in the **Analytics** page.

---

## Known Limitations

- **Synthetic corpus for live detection** - the host-behavioural evaluation uses deterministic synthetic scenarios, not real traffic. The separate network-flow detector is validated on real UNSW-NB15 data but is offline.
- **Response execution is simulated** - no firewall, AD, EDR, or hypervisor integration. Every payload carries `mode: "simulated"`, `integration: "none"`, `enforced: false`.
- **MITRE coverage is partial** - 49 of ~625 Enterprise techniques, no sub-techniques.
- **MTTD/MTTR baseline** is an external industry reference, not measured in this environment.
- **Audit trail** is in-memory and does not survive a restart.

---

## Project Structure

```
├── backend/
│   ├── app/
│   │   ├── api/             # 18 REST route files
│   │   ├── world_model/     # Bayesian engine, entity state, forecast, counterfactual
│   │   ├── agents/          # 14 AI agents (behaviour, MITRE, prediction, response, ...)
│   │   ├── ml/              # IsolationForest detector, sequence model, graph embedder
│   │   ├── services/        # Telemetry normalizers, threat intel, analytics
│   │   ├── evaluation/      # Labelled corpus + detection/attribution/response/timing
│   │   ├── scenarios/       # 3 labelled APT chains
│   │   ├── core/            # Config, database, auth, event bus, logging
│   │   ├── models/          # SQLAlchemy ORM
│   │   └── schemas/         # Pydantic V2 schemas
│   ├── models/              # Trained ML artifacts
│   ├── tests/               # 87+ tests
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── app/             # 14 Next.js pages
│   │   ├── components/      # UI components & page-level widgets
│   │   └── lib/             # API client, hooks, utilities
│   ├── public/              # Static assets
│   └── package.json
├── scripts/                 # Training & demo scripts
├── ARCHITECTURE.md
├── API_CONTRACT.md
└── AGENTS.md
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Frontend | Next.js 14, React 18, TypeScript, TailwindCSS, React Flow, Three.js, Recharts, Radix UI |
| Backend | FastAPI, Python 3.12, SQLAlchemy async, Pydantic V2 |
| Database | SQLite (default) / PostgreSQL |
| ML | scikit-learn (IsolationForest, RandomForest), NumPy, NetworkX |
| Threat Intel | MITRE ATT&CK, CISA KEV, NVD |
| Telemetry | Windows/Sysmon, Linux/auditd, Zeek, Suricata, Wazuh, Firewall, CloudTrail |
| Optional | Neo4j, Qdrant, Redis, Ollama, sentence-transformers |

---

## Tests

```bash
cd backend
python -m pytest -q
```