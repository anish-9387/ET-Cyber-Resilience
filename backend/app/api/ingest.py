import math
from typing import Any, Dict, List, Optional, Tuple
from datetime import datetime, timezone
from collections import defaultdict

from fastapi import APIRouter, Body, HTTPException
from pydantic import BaseModel, Field

from app.core.logger import logger
from app.core.database import async_session
from app.models import Event, EventCategory, EventSeverity
from app.services.event_processor import event_processor, UnifiedEvent
from app.agents.behaviour_agent import BehaviourLearningAgent
from app.agents.mitre_mapper import mitre_mapper

try:
    from app.world_model import world_model, Observation
    WORLD_MODEL_AVAILABLE = True
except ImportError:
    world_model = None
    Observation = None
    WORLD_MODEL_AVAILABLE = False

router = APIRouter()

behaviour_agent = BehaviourLearningAgent()

SEVERITY_MULTIPLIER = {
    "critical": 2.0,
    "high": 1.5,
    "medium": 1.0,
    "low": 0.7,
    "info": 0.5,
}

HIGH_IMPACT_TECHNIQUES = {
    "T1486": 1.6,   # Data Encrypted for Impact
    "T1490": 1.6,   # Inhibit System Recovery
    "T1485": 1.5,   # Data Destruction
    "T1003": 1.5,   # OS Credential Dumping
    "T1048": 1.4,   # Exfiltration Over Alternative Protocol
    "T1567": 1.4,   # Exfiltration Over Web Service
    "T1021": 1.3,   # Remote Services
    "T1562": 1.3,   # Impair Defenses
    "T1055": 1.2,   # Process Injection
}

# Absence of evidence is only weak evidence of absence. A single quiet
# observation may not claim more than 2:1 odds *against* compromise: routine
# activity continues on hosts that are already owned, and attackers blend into
# it deliberately. At the previous 0.05 floor one benign logon contributed
# log(0.11) = -2.2, enough to cancel out a ransomware detection on the same
# host and leave a visibly encrypted server reading as healthy.
LR_FLOOR = 0.5
LR_CEILING = 50.0

# ---------------------------------------------------------------------------
# Anomaly-score -> likelihood-ratio calibration
# ---------------------------------------------------------------------------
# log LR_anomaly(s) = ANOMALY_LR_INTERCEPT + ANOMALY_LR_SLOPE * s
#
# These two numbers are NOT hand-picked. They are fit by
# `app.evaluation.calibration` (run `python -m app.evaluation.calibration` to
# re-derive and print them) as a one-feature logistic regression of the
# malicious label on the fused anomaly score, over the CALIBRATION slice of the
# chronological three-way split - never over the holdout slice that
# `detection_eval` reports. The fitted posterior
#
#     P(malicious | s) = sigmoid(b0 + b1 * s)
#
# is converted to a likelihood ratio by dividing out the calibration split's
# class prior, which is Bayes' rule rearranged:
#
#     LR(s) = [P(mal|s)/P(ben|s)] / [P(mal)/P(ben)] = exp(b0 + b1*s) / prior_odds
#
# hence INTERCEPT = b0 - log(prior_odds) and SLOPE = b1. Dividing the prior out
# matters: the world model applies its own prior, so leaving the corpus base
# rate inside the "likelihood ratio" would double-count it.
#
# What this fixes: the previous mapping used a hand-picked linear response whose
# neutral point (LR = 1) sat at an anomaly score of ~0.486. Genuine malicious
# events score 0.35-0.55, so about half of every intrusion's evidence had
# LR < 1 and actively pushed P(compromised) DOWN. The fitted neutral point is
#
#     s* = -INTERCEPT / SLOPE = 0.5864
#
# which is where the calibration data actually puts the crossover, and it sits
# above the benign mass rather than through the middle of the attack steps.
#
# Fit provenance (seed 20260720, sentinel-synthetic-hospital-v1):
#   calibration slice 836 records, 42 malicious / 794 benign
#   b0 = -14.165535, b1 = 19.143826, prior odds = 0.052897
# Re-run the calibration module after any change to the detector or the corpus;
# these constants describe a specific detector's score distribution.
ANOMALY_LR_INTERCEPT = -11.226122
ANOMALY_LR_SLOPE = 19.143826

WINDOWS_BEHAVIOUR_EVENTS = {
    4625: "logon_failure",
    4697: "service_install",
    4698: "scheduled_task_created",
    4699: "scheduled_task_created",
    1102: "audit_log_cleared",
    104: "audit_log_cleared",
    4720: "account_created",
    4726: "account_deleted",
}

OT_HINTS = ("scada", "plc", "hmi", "rtu", "historian", "modbus", "dnp3", "ics", "pump", "valve")
SERVER_HINTS = ("srv", "server", "dc0", "dc1", "sql", "backup", "vcenter", "esx", "nas", "san")


class IngestStats:
    def __init__(self):
        self.total = 0
        self.by_source: Dict[str, int] = defaultdict(int)
        self.anomalous = 0
        self.mapped = 0
        self.persisted = 0
        self.persistence_failures = 0
        self.world_model_updates = 0
        self.errors = 0
        self.last_event_at: Optional[str] = None
        self.started_at = datetime.now(timezone.utc).isoformat()

    def snapshot(self) -> Dict[str, Any]:
        return {
            "total_events": self.total,
            "by_source": dict(self.by_source),
            "anomalous_events": self.anomalous,
            "mitre_mapped": self.mapped,
            "persisted": self.persisted,
            "persistence_failures": self.persistence_failures,
            "world_model_updates": self.world_model_updates,
            "errors": self.errors,
            "last_event_at": self.last_event_at,
            "started_at": self.started_at,
        }


stats = IngestStats()


class BatchIngestRequest(BaseModel):
    events: List[Dict[str, Any]] = Field(default_factory=list)


def derive_likelihood_ratio(
    anomaly_score: float,
    severity: str,
    technique_id: Optional[str],
    mitre_confidence: float = 0.0,
) -> Dict[str, Any]:
    """Bayesian likelihood ratio LR = P(observation | compromised) / P(observation | benign).

    Three explainable factors, multiplied:

    1. Anomaly term. The behaviour agent's fused score `a` in [0, 1] is mapped
       to P(a | compromised) / P(a | benign) by the log-linear form fitted in
       `app.evaluation.calibration` (see ANOMALY_LR_INTERCEPT above):

           log LR_anomaly(a) = ANOMALY_LR_INTERCEPT + ANOMALY_LR_SLOPE * a

       This replaces a hand-picked pair of linear class-conditionals whose
       neutral point fell at a ~= 0.486, below where real attack steps score,
       so half of every intrusion's evidence was exculpatory. The fitted
       crossover is a ~= 0.5864. Quiet events are exculpatory but only weakly:
       the LR_FLOOR clamp below caps how much any single quiet observation may
       argue against compromise.

    2. Severity multiplier. The source's own severity grading, 0.5x (info) to
       2.0x (critical) - independent evidence from the sensor's rule set.

    3. Technique multiplier. Unmapped events get 1.0. A MITRE mapping adds
       `1 + 0.5 * confidence`; techniques that are late-kill-chain and rarely
       benign (encryption for impact, backup destruction, credential dumping)
       carry an extra weight from HIGH_IMPACT_TECHNIQUES.

    The product is clamped to [LR_FLOOR, LR_CEILING] so no single observation
    can drive a belief to certainty - in either direction - on its own.
    """
    a = max(0.0, min(float(anomaly_score), 1.0))
    log_anomaly_lr = ANOMALY_LR_INTERCEPT + ANOMALY_LR_SLOPE * a
    # Bound the exponent before exponentiating; the product is clamped to
    # [LR_FLOOR, LR_CEILING] below anyway, so this only avoids overflow.
    anomaly_term = math.exp(max(-30.0, min(log_anomaly_lr, 30.0)))

    severity_term = SEVERITY_MULTIPLIER.get((severity or "info").lower(), 1.0)

    if technique_id:
        technique_term = (1.0 + 0.5 * max(0.0, min(mitre_confidence, 1.0)))
        technique_term *= HIGH_IMPACT_TECHNIQUES.get(technique_id, 1.0)
    else:
        technique_term = 1.0

    raw = anomaly_term * severity_term * technique_term
    likelihood_ratio = max(LR_FLOOR, min(raw, LR_CEILING))

    return {
        "likelihood_ratio": round(likelihood_ratio, 4),
        "factors": {
            "anomaly_term": round(anomaly_term, 4),
            "log_anomaly_lr": round(log_anomaly_lr, 4),
            "severity_term": severity_term,
            "technique_term": round(technique_term, 4),
            "raw_product": round(raw, 4),
            "clamped": raw != likelihood_ratio,
        },
        "explanation": (
            f"LR = {anomaly_term:.2f} (anomaly {a:.2f}) "
            f"x {severity_term:.2f} (severity {severity}) "
            f"x {technique_term:.2f} (technique {technique_id or 'unmapped'}) "
            f"= {likelihood_ratio:.2f}"
        ),
    }


def derive_entity(normalized: Dict[str, Any], raw: Dict[str, Any]) -> Tuple[str, str]:
    candidates = [
        normalized.get("computer"),
        normalized.get("hostname"),
        normalized.get("agent"),
        normalized.get("device"),
        raw.get("entity_id"),
        raw.get("host"),
        normalized.get("src_ip"),
        normalized.get("source_ip"),
        normalized.get("user"),
    ]
    entity_id = next((str(c) for c in candidates if c), "unknown-entity")
    lowered = entity_id.lower()

    if any(h in lowered for h in OT_HINTS):
        entity_type = "ot"
    elif any(h in lowered for h in SERVER_HINTS):
        entity_type = "server"
    elif normalized.get("category") == "network" and not normalized.get("computer"):
        entity_type = "device"
    elif entity_id == str(normalized.get("user") or ""):
        entity_type = "user"
    else:
        entity_type = "device"

    return entity_id, entity_type


def resolve_or_discover(observed_identifier: str, entity_type: str) -> Dict[str, Any]:
    """Map a telemetry identifier onto a modelled asset before observing it.

    Sensors report hostnames ("HOSP-BKP01"), never world-model ids
    ("srv-backup-01"). Resolving first is what keeps evidence on the seeded
    topology; creating an entity per hostname produced orphan nodes with no
    relations, so nothing downstream could reason over them.

    A genuine resolution failure is not swallowed: an unrecognised asset
    transmitting on the network is itself a finding, so it is registered as
    unmanaged/discovered and logged.
    """
    if not WORLD_MODEL_AVAILABLE:
        return {"status": "unavailable", "entity_id": observed_identifier,
                "observed_identifier": observed_identifier, "resolved": False, "discovered": False}

    entity = world_model.resolve(observed_identifier)
    if entity is not None:
        return {
            "status": "resolved",
            "resolved": True,
            "discovered": False,
            "entity_id": entity.id,
            "entity_name": entity.name,
            "observed_identifier": observed_identifier,
            "matched_as": "identity" if entity.id == observed_identifier else "alias_or_hostname",
        }

    entity = world_model.discover_entity(
        identifier=observed_identifier,
        entity_type=entity_type,
        name=observed_identifier,
    )
    logger.warning(
        "Unmanaged asset observed on the network",
        observed_identifier=observed_identifier,
        entity_type=entity_type,
        note="no seeded asset matched this identifier; registered as unmanaged/discovered",
    )
    return {
        "status": "discovered",
        "resolved": False,
        "discovered": True,
        "entity_id": entity.id,
        "entity_name": entity.name,
        "observed_identifier": observed_identifier,
        "matched_as": None,
        "finding": "unmanaged asset present on the network",
    }


def build_behaviour_input(entity_id: str, entity_type: str, normalized: Dict[str, Any],
                          raw: Dict[str, Any]) -> Dict[str, Any]:
    windows_id = raw.get("EventID") or raw.get("EventId")
    event_type = WINDOWS_BEHAVIOUR_EVENTS.get(
        int(windows_id) if str(windows_id).isdigit() else None,
        normalized.get("event_type", "unknown"),
    )

    payload: Dict[str, Any] = {
        "action": "analyze",
        "entity_id": entity_id,
        "entity_type": entity_type,
        "event_type": event_type,
        "severity": normalized.get("severity", "info"),
    }

    timestamp = parse_timestamp(normalized.get("timestamp"))
    payload["login_time"] = timestamp.hour
    payload["day_of_week"] = timestamp.weekday()
    payload["timestamp"] = timestamp.isoformat()

    for key, source_keys in (
        ("location", ("location", "geo", "country", "aws_region")),
        ("resource", ("resource", "object_name", "share_name", "target_file")),
        ("command", ("command", "command_line", "process_command_line", "CommandLine")),
        ("destination_ip", ("dst_ip", "destination_ip", "dest_ip")),
        ("data_size", ("data_size", "bytes", "resp_bytes", "orig_bytes")),
        ("port", ("dst_port", "destination_port")),
    ):
        for sk in source_keys:
            value = normalized.get(sk, raw.get(sk))
            if value not in (None, ""):
                payload[key] = value
                break

    context = f"{normalized.get('title') or ''} {normalized.get('description') or ''}".strip()
    command = str(payload.get("command") or "")
    combined = f"{command} {context}".strip()
    if combined:
        payload["command"] = combined[:1000]

    return payload


def parse_timestamp(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (ValueError, OSError, OverflowError):
            return datetime.now(timezone.utc)
    if isinstance(value, str):
        candidate = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)


async def persist_event(unified: UnifiedEvent, anomaly: Dict[str, Any],
                        mitre: Dict[str, Any]) -> Optional[str]:
    """Best-effort Postgres write; returns the row id or None if the DB is down."""
    normalized = unified.normalized
    try:
        severity = EventSeverity(str(normalized.get("severity", "info")).lower())
    except ValueError:
        severity = EventSeverity.INFO
    try:
        category = EventCategory(str(normalized.get("category", "system")).lower())
    except ValueError:
        category = EventCategory.SYSTEM

    row = Event(
        event_type=str(normalized.get("event_type", "unknown"))[:100],
        category=category,
        severity=severity,
        source=str(normalized.get("source", unified.source))[:200],
        title=str(normalized.get("title") or "Ingested event")[:300],
        description=str(normalized.get("description") or ""),
        raw_data=unified.raw_event,
        metadata_={
            "normalized": normalized,
            "anomaly": anomaly,
            "mitre": mitre,
            "processing_errors": unified.processing_errors,
        },
        tags=[unified.source, str(normalized.get("event_type", "unknown"))],
        timestamp=parse_timestamp(normalized.get("timestamp")),
        processed=True,
    )

    try:
        async with async_session() as session:
            session.add(row)
            await session.commit()
        stats.persisted += 1
        return row.id
    except Exception as e:
        stats.persistence_failures += 1
        logger.warning("Event persistence failed, continuing in-memory", error=str(e))
        return None


def _entity_delta(entity_ids: List[str], before: Dict[str, float]) -> Dict[str, Any]:
    if not WORLD_MODEL_AVAILABLE:
        return {"available": False, "entities": []}

    entities = []
    for eid in entity_ids:
        entity = world_model.get_entity(eid)
        if entity is None:
            continue
        after = float(getattr(entity, "p_compromised", 0.0))
        prior = before.get(eid, 0.0)
        entities.append({
            "entity_id": eid,
            "p_compromised_before": round(prior, 6),
            "p_compromised_after": round(after, 6),
            "delta": round(after - prior, 6),
            "state": getattr(entity, "state", None),
            "confidence": getattr(entity, "confidence", None),
        })
    return {"available": True, "entities": entities}


async def ingest_raw_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    """Full pipeline for one raw telemetry record.

    normalize -> behaviour anomaly score -> MITRE mapping -> likelihood ratio
    -> world model observation -> Postgres persistence.
    """
    payload = dict(raw_event)
    ground_truth = payload.pop("ground_truth", None)
    payload.pop("offset_seconds", None)
    source_type = str(payload.pop("source_type", None) or payload.get("source") or "custom").lower()

    unified = await event_processor.process(payload, source_type)
    normalized = unified.normalized

    entity_id, entity_type = derive_entity(normalized, payload)

    try:
        anomaly = await behaviour_agent.process(
            build_behaviour_input(entity_id, entity_type, normalized, payload)
        )
    except Exception as e:
        logger.warning("Behaviour analysis failed", entity_id=entity_id, error=str(e))
        anomaly = {"success": False, "anomaly_score": 0.0, "detector": "rules",
                   "baseline_samples": 0, "error": str(e)}

    anomaly_score = float(anomaly.get("anomaly_score", 0.0) or 0.0)

    mitre = mitre_mapper.map_event({
        "event_type": normalized.get("event_type", ""),
        "description": f"{normalized.get('title', '')} {normalized.get('description', '')}",
    })

    severity = str(normalized.get("severity", "info")).lower()
    lr = derive_likelihood_ratio(
        anomaly_score=anomaly_score,
        severity=severity,
        technique_id=mitre.get("technique_id"),
        mitre_confidence=float(mitre.get("confidence", 0.0) or 0.0),
    )

    timestamp = parse_timestamp(normalized.get("timestamp"))
    updated_entities: List[str] = []
    before: Dict[str, float] = {}
    resolution = resolve_or_discover(entity_id, entity_type)
    world_model_entity_id = resolution["entity_id"]

    if WORLD_MODEL_AVAILABLE:
        existing = world_model.get_entity(world_model_entity_id)
        if existing is not None:
            before[world_model_entity_id] = float(getattr(existing, "p_compromised", 0.0))
        try:
            observation = Observation(
                entity_id=world_model_entity_id,
                source=str(normalized.get("source", source_type)),
                description=str(normalized.get("title") or normalized.get("description") or "")[:500],
                technique_id=mitre.get("technique_id"),
                likelihood_ratio=lr["likelihood_ratio"],
                severity=severity,
                timestamp=timestamp,
                raw=payload,
            )
            updated_entities = await world_model.ingest_observation(observation) or []
            stats.world_model_updates += len(updated_entities)
        except Exception as e:
            logger.warning("World model ingest failed", entity_id=world_model_entity_id, error=str(e))

    event_id = await persist_event(unified, anomaly, mitre)

    stats.total += 1
    stats.by_source[source_type] += 1
    stats.last_event_at = timestamp.isoformat()
    if anomaly.get("is_anomalous"):
        stats.anomalous += 1
    if mitre.get("mapped"):
        stats.mapped += 1

    result = {
        "event_id": event_id or f"mem-{entity_id}-{stats.total}",
        "persisted": event_id is not None,
        "entity_id": world_model_entity_id,
        "observed_identifier": entity_id,
        "entity_resolution": resolution,
        "entity_type": entity_type,
        "normalized": normalized,
        "anomaly": {
            "anomaly_score": round(anomaly_score, 4),
            "rule_score": anomaly.get("rule_score"),
            "model_score": anomaly.get("model_score"),
            "detector": anomaly.get("detector", "rules"),
            "baseline_samples": anomaly.get("baseline_samples", 0),
            "is_anomalous": bool(anomaly.get("is_anomalous", False)),
            "risk_score": anomaly.get("risk_score", 0.0),
            "reasons": [r for a in anomaly.get("anomalies", []) for r in a.get("reasons", [])][:10],
        },
        "mitre": mitre,
        "likelihood_ratio": lr,
        "updated_entities": updated_entities,
        "world_model_delta": _entity_delta(updated_entities or [world_model_entity_id], before),
    }

    if ground_truth:
        result["ground_truth"] = ground_truth

    return result


@router.post("/event")
async def ingest_event(raw_event: Dict[str, Any] = Body(...)):
    if not raw_event:
        raise HTTPException(status_code=400, detail="Empty event body")
    try:
        return await ingest_raw_event(raw_event)
    except Exception as e:
        stats.errors += 1
        logger.error("Ingest failed", error=str(e))
        raise HTTPException(status_code=500, detail=f"Ingest failed: {e}")


@router.post("/batch")
async def ingest_batch(request: BatchIngestRequest):
    if not request.events:
        raise HTTPException(status_code=400, detail="No events supplied")

    results: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    updated: set = set()

    for index, raw_event in enumerate(request.events):
        try:
            result = await ingest_raw_event(raw_event)
            results.append(result)
            updated.update(result.get("updated_entities") or [])
        except Exception as e:
            stats.errors += 1
            failures.append({"index": index, "error": str(e)})
            logger.warning("Batch item failed", index=index, error=str(e))

    anomalous = [r for r in results if r["anomaly"]["is_anomalous"]]
    return {
        "received": len(request.events),
        "processed": len(results),
        "failed": len(failures),
        "failures": failures[:20],
        "anomalous_count": len(anomalous),
        "resolved_count": len([r for r in results if r["entity_resolution"]["resolved"]]),
        "discovered_entities": sorted({
            r["entity_resolution"]["observed_identifier"]
            for r in results
            if r["entity_resolution"]["discovered"]
        }),
        "mapped_count": len([r for r in results if r["mitre"].get("mapped")]),
        "updated_entities": sorted(updated),
        "max_likelihood_ratio": max(
            (r["likelihood_ratio"]["likelihood_ratio"] for r in results), default=0.0
        ),
        "events": [
            {
                "event_id": r["event_id"],
                "entity_id": r["entity_id"],
                "technique_id": r["mitre"].get("technique_id"),
                "anomaly_score": r["anomaly"]["anomaly_score"],
                "likelihood_ratio": r["likelihood_ratio"]["likelihood_ratio"],
            }
            for r in results
        ],
    }


@router.get("/status")
async def ingest_status():
    detectors = {
        entity_type: {
            "fitted": detector.is_fitted,
            "baseline_samples": behaviour_agent.baseline_samples(entity_type),
        }
        for entity_type, detector in behaviour_agent.detectors.items()
    }

    world_model_state: Dict[str, Any] = {"available": WORLD_MODEL_AVAILABLE}
    if WORLD_MODEL_AVAILABLE:
        try:
            entities = world_model.all_entities()
            world_model_state.update({
                "entity_count": len(entities),
                "compromised_count": len(
                    [e for e in entities if float(getattr(e, "p_compromised", 0.0)) > 0.5]
                ),
            })
        except Exception as e:
            world_model_state["error"] = str(e)

    return {
        "status": "healthy",
        "pipeline": stats.snapshot(),
        "supported_sources": event_processor.get_stats()["supported_sources"],
        "detectors": detectors,
        "min_baseline_samples": behaviour_agent.min_baseline_samples,
        "world_model": world_model_state,
    }
