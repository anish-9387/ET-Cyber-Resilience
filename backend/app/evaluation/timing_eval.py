"""MTTD / MTTR measured from the world model's actual observation log.

Method
------
For each attack scenario in the corpus, the harness replays that scenario's
telemetry through the **real** production pipeline:

    record -> BehaviourLearningAgent (anomaly score)
           -> MitreMapper (technique)
           -> api.ingest.derive_likelihood_ratio (LR)
           -> world_model.ingest_observation (Bayesian belief update)

**MTTD** is the elapsed scenario time from the first *ground-truth malicious*
event to the first observation after which the affected entity's
``p_compromised`` crosses the detection threshold. It is read off the belief
trajectory, not asserted. Scenarios that never cross the threshold are reported
as ``detected: false`` and are **excluded from the mean** - averaging only over
successes would report a fast MTTD for a detector that misses most attacks, so
``detection_coverage`` must be read alongside the mean.

**MTTR** is the elapsed time from that detection to the decision engine
returning a recommended containment option.

WHAT MTTR HERE DOES *NOT* INCLUDE
---------------------------------
* Human approval wait. Most containment playbooks gate on a human
  (``ask_approval`` / ``immediate``); that queue time is real MTTR in a SOC and
  is not simulated here.
* Actual containment. Execution is simulated (see ``response_eval``); no
  firewall or directory is touched, so nothing is genuinely *resolved*.

The reported ``sentinel_mttr_minutes`` is therefore **time-to-recommendation**,
not time-to-resolution, and is labelled as such in the payload. Comparing it to
an industry MTTR that measures full remediation would be dishonest, so the
payload carries an explicit ``comparability`` block.

THE SEED-DATA TRAP
------------------
``scripts/create_sample_incidents.py`` plants hardcoded ``mttr_minutes`` values
(3-47) into seed incidents, which ``GET /analytics/mttr`` then averages and
reports as if measured. This module never reads incident seed data. Everything
below is derived from replayed observation timestamps.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from app.evaluation.datasets import (
    BenchmarkDataset,
    LabeledRecord,
    generate_benchmark_dataset,
    logger,
)

# --------------------------------------------------------------------------
# Baseline SOC reference figures - EXTERNAL, NOT MEASURED HERE
# --------------------------------------------------------------------------

#: Mean time to identify a breach, global all-industry average, in days.
BASELINE_MTTD_DAYS = 194.0
#: Mean time to contain a breach once identified, in days.
BASELINE_MTTR_DAYS = 64.0
#: Healthcare-sector breach lifecycle (identify + contain), in days.
BASELINE_HEALTHCARE_LIFECYCLE_DAYS = 279.0

BASELINE_SOURCE = (
    "IBM Security / Ponemon Institute, 'Cost of a Data Breach Report 2024'. "
    "Global average mean time to identify (MTTI) 194 days and mean time to "
    "contain (MTTC) 64 days, for a 258-day mean breach lifecycle; the "
    "healthcare sector averages ~279 days."
)
BASELINE_IS_EXTERNAL = True

BASELINE_COMPARABILITY_WARNING = (
    "THESE BASELINE FIGURES ARE AN EXTERNAL INDUSTRY REFERENCE, NOT A "
    "MEASUREMENT OF A SOC THIS PROJECT RAN. They describe full breach "
    "lifecycles in production enterprises - including dwell time before any "
    "telemetry is collected, triage backlogs, staffing constraints, and "
    "end-to-end remediation. The Overlook figures below are measured on a "
    "replay of a pre-collected, fully-instrumented synthetic scenario where "
    "every relevant event is guaranteed present and is processed instantly. "
    "The improvement percentages are therefore NOT a like-for-like comparison "
    "and must not be presented as evidence that Overlook reduces real-world "
    "MTTD/MTTR by that factor. They are reported only because the evaluation "
    "criteria call for a baseline comparison; the honest reading is that they "
    "quantify pipeline latency on ideal input, not operational improvement."
)

#: Belief threshold at which an entity counts as detected. Defaults to the
#: world model's own DETECTION_THRESHOLD so the harness and the product agree.
try:  # pragma: no cover - depends on a module owned by another agent
    from app.world_model.model import DETECTION_THRESHOLD as _WM_DETECTION_THRESHOLD
except Exception:  # pragma: no cover
    _WM_DETECTION_THRESHOLD = 0.5

DEFAULT_DETECTION_THRESHOLD = float(_WM_DETECTION_THRESHOLD)

try:  # pragma: no cover
    from app.world_model import world_model, Observation

    WORLD_MODEL_AVAILABLE = True
except ImportError:  # pragma: no cover
    world_model = None  # type: ignore[assignment]
    Observation = None  # type: ignore[assignment]
    WORLD_MODEL_AVAILABLE = False


def _minutes_between(start: datetime, end: datetime) -> float:
    return max((end - start).total_seconds() / 60.0, 0.0)


async def _replay_scenario(
    scenario_id: str,
    records: List[LabeledRecord],
    baseline_records: List[LabeledRecord],
    detection_threshold: float,
) -> Dict[str, Any]:
    """Replay one scenario and read MTTD/MTTR off the belief trajectory."""
    from app.agents.behaviour_agent import BehaviourLearningAgent
    from app.agents.mitre_mapper import mitre_mapper
    from app.api.ingest import derive_likelihood_ratio

    world_model.reset()

    # Give the detector a benign behavioural baseline, exactly as it would have
    # in production before an attack begins.
    agent = BehaviourLearningAgent()
    for record in baseline_records:
        profile = agent._get_or_create_profile(record.entity_id, record.entity_type)
        agent._update_profile_from_record(profile, record.to_behaviour_input())
        agent._record_sample(profile)
    for entity_type in sorted({r.entity_type for r in baseline_records}):
        agent.train_baseline(entity_type, force=True)

    ordered = sorted(records, key=lambda r: r.timestamp)
    malicious = [r for r in ordered if r.is_malicious]
    if not malicious:
        return {"scenario_id": scenario_id, "skipped": "no malicious records"}

    first_malicious_at = malicious[0].timestamp

    # Evidence attribution: the world model files evidence against the RESOLVED
    # asset, not the identifier the sensor reported. Scenario telemetry carries
    # hostnames ("WTR-ENG02"); the seeded topology knows them as
    # "ws-wtr-eng02". Tracking the raw identifier here meant every belief lookup
    # missed the entity the evidence had actually landed on, so p_compromised
    # read ~0 for entities the model had already raised to 0.97 - which is why
    # 12/12 scenarios reported undetected while the audit log showed
    # detections. `api.ingest` resolves before observing (resolve_or_discover);
    # the evaluation path now does the same, which is the point of the harness.
    def _resolved_id(identifier: str, entity_type: str) -> str:
        entity = world_model.resolve(identifier)
        if entity is not None:
            return entity.id
        return world_model.discover_entity(
            identifier=identifier, entity_type=entity_type, name=identifier,
        ).id

    resolved: Dict[str, str] = {
        record.entity_id: _resolved_id(record.entity_id, record.entity_type)
        for record in ordered
    }
    affected_entities = {resolved[r.entity_id] for r in malicious}

    detected_at: Optional[datetime] = None
    detected_entity: Optional[str] = None
    detected_p: Optional[float] = None
    observations_until_detection = 0
    trajectory: List[Dict[str, Any]] = []

    # Threshold sensitivity: the first crossing time for a range of candidate
    # thresholds, so a 0% detection rate at the shipped threshold can be
    # diagnosed (is the belief close, or nowhere near?) instead of just
    # reported as a failure.
    candidate_thresholds = [0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9]
    crossings: Dict[float, Optional[datetime]] = {t: None for t in candidate_thresholds}

    for record in ordered:
        event = record.to_behaviour_input()

        profile = agent._get_or_create_profile(record.entity_id, record.entity_type)
        agent._update_profile_from_record(profile, event)
        agent._record_sample(profile)
        model = agent._model_score(profile)
        rule = agent._detect_anomalies(profile, event)
        anomaly_score, _path = agent._combine_scores(
            float(rule.get("score", 0.0)), model,
            float(rule.get("specific_score", 0.0)),
        )

        mitre = mitre_mapper.map_event(record.to_event())
        lr = derive_likelihood_ratio(
            anomaly_score=float(anomaly_score),
            severity=record.severity,
            technique_id=mitre.get("technique_id"),
            mitre_confidence=float(mitre.get("confidence", 0.0) or 0.0),
        )

        await world_model.ingest_observation(Observation(
            entity_id=resolved[record.entity_id],
            source=record.source,
            description=record.description[:500],
            technique_id=mitre.get("technique_id"),
            likelihood_ratio=lr["likelihood_ratio"],
            severity=record.severity,
            timestamp=record.timestamp,
            raw={"entity_type": record.entity_type, "record_id": record.record_id},
        ))

        if record.timestamp >= first_malicious_at:
            observations_until_detection += 1

        entity = world_model.get_entity(resolved[record.entity_id])
        p_compromised = float(getattr(entity, "p_compromised", 0.0)) if entity else 0.0
        trajectory.append({
            "record_id": record.record_id,
            "timestamp": record.timestamp.isoformat(),
            "entity_id": resolved[record.entity_id],
            "observed_identifier": record.entity_id,
            "is_malicious": record.is_malicious,
            "anomaly_score": round(float(anomaly_score), 4),
            "likelihood_ratio": lr["likelihood_ratio"],
            "p_compromised": round(p_compromised, 4),
        })

        if record.timestamp >= first_malicious_at:
            # Highest belief currently held about any entity the attack touched.
            peak_now = 0.0
            peak_entity: Optional[str] = None
            for entity_id in affected_entities:
                candidate = world_model.get_entity(entity_id)
                if candidate is None:
                    continue
                p_value = float(getattr(candidate, "p_compromised", 0.0))
                if p_value > peak_now:
                    peak_now, peak_entity = p_value, entity_id

            for candidate_threshold in candidate_thresholds:
                if crossings[candidate_threshold] is None and peak_now >= candidate_threshold:
                    crossings[candidate_threshold] = record.timestamp

            if detected_at is None and peak_now >= detection_threshold:
                detected_at = record.timestamp
                detected_entity = peak_entity
                detected_p = peak_now

    result: Dict[str, Any] = {
        "scenario_id": scenario_id,
        "first_malicious_at": first_malicious_at.isoformat(),
        "malicious_events": len(malicious),
        "total_events": len(ordered),
        "affected_entities": sorted(affected_entities),
        "detection_threshold": detection_threshold,
        "detected": detected_at is not None,
        "peak_p_compromised": round(
            max((t["p_compromised"] for t in trajectory), default=0.0), 4
        ),
        "threshold_sensitivity": {
            str(threshold): (
                round(_minutes_between(first_malicious_at, crossed), 4)
                if crossed else None
            )
            for threshold, crossed in crossings.items()
        },
        "belief_trajectory": trajectory,
    }

    if detected_at is None:
        result.update({
            "mttd_minutes": None,
            "mttr_minutes": None,
            "note": (
                f"No affected entity's p_compromised reached "
                f"{detection_threshold} at any point in this scenario. MTTD is "
                "undefined - the attack was never detected. This scenario is "
                "excluded from the mean MTTD and counted against "
                "detection_coverage."
            ),
        })
        return result

    mttd_minutes = _minutes_between(first_malicious_at, detected_at)

    # MTTR: detection -> decision engine returns a recommended containment
    # option. Wall-clock latency of the real call is measured; scenario-time
    # elapsed is zero because the recommendation is produced synchronously at
    # the detection instant.
    from app.world_model.decision_engine import decision_engine

    started = time.perf_counter()
    options_payload = decision_engine.options()
    decision_latency_seconds = time.perf_counter() - started

    options = options_payload.get("options", []) or []
    recommended_id = options_payload.get("recommended_id")
    recommended = next(
        (o for o in options if o.get("id") == recommended_id),
        options[0] if options else None,
    )

    result.update({
        "detected_at": detected_at.isoformat(),
        "detected_entity": detected_entity,
        "p_compromised_at_detection": round(detected_p or 0.0, 4),
        "observations_until_detection": observations_until_detection,
        "mttd_minutes": round(mttd_minutes, 4),
        "recommendation_available": recommended is not None,
        "recommended_option": (
            {
                "id": recommended.get("id"),
                "action": recommended.get("action"),
                "approval_required": recommended.get("approval_required"),
                "risk_level": recommended.get("risk_level"),
            } if recommended else None
        ),
        "options_generated": len(options),
        "decision_latency_seconds": round(decision_latency_seconds, 6),
        "mttr_minutes": round(decision_latency_seconds / 60.0, 6),
        "mttr_semantics": "time_to_recommendation",
        "mttr_excludes_human_approval_wait": True,
        "mttr_excludes_real_containment": True,
        "requires_human_approval": bool(
            recommended.get("approval_required") if recommended else False
        ),
    })
    return result


async def evaluate_timing(
    dataset: Optional[BenchmarkDataset] = None,
    detection_threshold: float = DEFAULT_DETECTION_THRESHOLD,
    max_scenarios: Optional[int] = None,
) -> Dict[str, Any]:
    """Measure MTTD/MTTR by replaying scenarios through the real pipeline.

    Returns:
        A payload matching ``GET /evaluation/mttd-mttr`` in the API contract,
        extended with per-scenario detail, detection coverage, and an explicit
        comparability warning on the baseline figures.
    """
    dataset = dataset or generate_benchmark_dataset()

    baseline_mttd_minutes = BASELINE_MTTD_DAYS * 24 * 60
    baseline_mttr_minutes = BASELINE_MTTR_DAYS * 24 * 60

    baseline_block = {
        "baseline_mttd_minutes": baseline_mttd_minutes,
        "baseline_mttr_minutes": baseline_mttr_minutes,
        "baseline_mttd_days": BASELINE_MTTD_DAYS,
        "baseline_mttr_days": BASELINE_MTTR_DAYS,
        "baseline_healthcare_lifecycle_days": BASELINE_HEALTHCARE_LIFECYCLE_DAYS,
        "baseline_source": BASELINE_SOURCE,
        "baseline_is_external_reference": BASELINE_IS_EXTERNAL,
        "baseline_was_measured_here": False,
        "comparability_warning": BASELINE_COMPARABILITY_WARNING,
    }

    if not WORLD_MODEL_AVAILABLE:
        return {
            **baseline_block,
            "error": (
                "app.world_model is unavailable, so P(compromised) trajectories "
                "cannot be replayed. MTTD/MTTR are NOT computable and no value "
                "is reported."
            ),
            "sentinel_mttd_minutes": None,
            "sentinel_mttr_minutes": None,
            "mttd_improvement_pct": None,
            "mttr_improvement_pct": None,
            "world_model_available": False,
            "provenance": dataset.provenance,
        }

    # Benign background from the earliest window trains the detector baseline.
    background = sorted(
        (r for r in dataset.records if not r.is_malicious and r.scenario_id is None),
        key=lambda r: r.timestamp,
    )
    baseline_records = background[: max(len(background) // 2, 1)]

    scenario_ids = [
        sid for sid in dataset.scenario_ids()
        if any(r.is_malicious for r in dataset.by_scenario(sid))
    ]
    if max_scenarios is not None:
        scenario_ids = scenario_ids[:max_scenarios]

    per_scenario: List[Dict[str, Any]] = []
    for scenario_id in scenario_ids:
        records = dataset.by_scenario(scenario_id)
        try:
            result = await _replay_scenario(
                scenario_id, records, baseline_records, detection_threshold
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "evaluation.timing: scenario replay failed",
                scenario_id=scenario_id, error=str(exc),
            )
            result = {"scenario_id": scenario_id, "error": str(exc), "detected": False}
        per_scenario.append(result)

    # Keep the full trajectory out of the summary payload; it is large.
    trajectories = {
        r["scenario_id"]: r.pop("belief_trajectory", [])
        for r in per_scenario if "belief_trajectory" in r
    }

    detected = [r for r in per_scenario if r.get("detected")]
    undetected = [r for r in per_scenario if not r.get("detected")]

    mttds = [r["mttd_minutes"] for r in detected if r.get("mttd_minutes") is not None]
    mttrs = [r["mttr_minutes"] for r in detected if r.get("mttr_minutes") is not None]

    sentinel_mttd = round(sum(mttds) / len(mttds), 4) if mttds else None
    sentinel_mttr = round(sum(mttrs) / len(mttrs), 6) if mttrs else None

    def _improvement(baseline: float, measured: Optional[float]) -> Optional[float]:
        if measured is None:
            return None
        return round(100.0 * (baseline - measured) / baseline, 4)

    detection_coverage = (
        round(len(detected) / len(per_scenario), 4) if per_scenario else 0.0
    )

    # Aggregate threshold sensitivity: what detection coverage and MTTD would
    # look like at other belief thresholds. This turns a 0% result into a
    # diagnosis rather than a dead end.
    sensitivity: List[Dict[str, Any]] = []
    scenarios_with_sensitivity = [
        r for r in per_scenario if isinstance(r.get("threshold_sensitivity"), dict)
    ]
    if scenarios_with_sensitivity:
        for threshold in sorted(
            scenarios_with_sensitivity[0]["threshold_sensitivity"], key=float
        ):
            times = [
                r["threshold_sensitivity"][threshold]
                for r in scenarios_with_sensitivity
                if r["threshold_sensitivity"].get(threshold) is not None
            ]
            sensitivity.append({
                "threshold": float(threshold),
                "scenarios_detected": len(times),
                "scenarios_total": len(scenarios_with_sensitivity),
                "detection_coverage": round(
                    len(times) / len(scenarios_with_sensitivity), 4
                ),
                "mean_mttd_minutes": (
                    round(sum(times) / len(times), 4) if times else None
                ),
            })

    peak_beliefs = [
        r["peak_p_compromised"] for r in per_scenario
        if r.get("peak_p_compromised") is not None
    ]

    payload: Dict[str, Any] = {
        # --- contract fields ---
        **baseline_block,
        "sentinel_mttd_minutes": sentinel_mttd,
        "sentinel_mttr_minutes": sentinel_mttr,
        "mttd_improvement_pct": _improvement(baseline_mttd_minutes, sentinel_mttd),
        "mttr_improvement_pct": _improvement(baseline_mttr_minutes, sentinel_mttr),
        # --- extended, honest detail ---
        "world_model_available": True,
        "detection_threshold": detection_threshold,
        "detection_threshold_source": "app.world_model.model.DETECTION_THRESHOLD",
        "scenarios_evaluated": len(per_scenario),
        "scenarios_detected": len(detected),
        "scenarios_undetected": len(undetected),
        "undetected_scenario_ids": [r["scenario_id"] for r in undetected],
        "detection_coverage": detection_coverage,
        "mttd_measured_over_detected_scenarios_only": True,
        "threshold_sensitivity": sensitivity,
        "mean_peak_p_compromised": (
            round(sum(peak_beliefs) / len(peak_beliefs), 4) if peak_beliefs else None
        ),
        "max_peak_p_compromised": round(max(peak_beliefs), 4) if peak_beliefs else None,
        "mttd_semantics": (
            "scenario-time minutes from first ground-truth malicious event to "
            "first crossing of the belief threshold by an affected entity"
        ),
        "mttr_semantics": "time_to_recommendation",
        "mttr_excludes_human_approval_wait": True,
        "mttr_excludes_real_containment": True,
        "world_model_internal_mttd_minutes": world_model.mttd_minutes(),
        "reads_incident_seed_data": False,
        "seed_data_trap_note": (
            "scripts/create_sample_incidents.py hardcodes mttr_minutes values "
            "(3-47) into seed incidents, and GET /analytics/mttr averages those "
            "literals and presents them as a measured metric. This module does "
            "not read incident seed data; every figure here is derived from "
            "replayed observation timestamps and belief trajectories."
        ),
        "per_scenario": per_scenario,
        "provenance": dataset.provenance,
        "caveats": [],
    }

    caveats: List[str] = []
    if dataset.provenance.get("is_synthetic"):
        caveats.append(
            "Scenario timelines are synthetic; MTTD reflects the simulated event "
            "spacing chosen by the scenario author, not observed attacker tempo."
        )
    caveats.append(BASELINE_COMPARABILITY_WARNING)
    if undetected:
        peak_text = (
            f" The highest belief reached on any affected entity across all "
            f"scenarios was {round(max(peak_beliefs), 4)} "
            f"(mean {round(sum(peak_beliefs) / len(peak_beliefs), 4)})."
            if peak_beliefs else ""
        )
        caveats.append(
            f"{len(undetected)} of {len(per_scenario)} scenarios were NEVER "
            f"detected (belief never reached {detection_threshold}). Their MTTD "
            "is infinite and they are excluded from the mean, so the reported "
            f"sentinel_mttd_minutes describes only the {len(detected)} scenarios "
            "that were caught. Read it together with detection_coverage="
            f"{detection_coverage}.{peak_text} See threshold_sensitivity for "
            "the coverage/MTTD tradeoff at other belief thresholds."
        )
    if not detected:
        caveats.append(
            "CRITICAL: no scenario was detected at the shipped belief threshold, "
            "so sentinel_mttd_minutes, sentinel_mttr_minutes and both "
            "improvement percentages are null. The pipeline did not detect any "
            "of these attacks end to end, and no MTTD/MTTR improvement over any "
            "baseline is demonstrated by this run."
        )
    if sentinel_mttr is not None:
        caveats.append(
            "sentinel_mttr_minutes is time-to-RECOMMENDATION (the decision "
            "engine returning a containment option), measured as real "
            "wall-clock latency. It is not time-to-resolution: it excludes "
            "human approval queue time, and containment execution is simulated, "
            "so nothing is actually remediated. The resulting "
            "mttr_improvement_pct compares a sub-second function call against "
            "an industry figure for full breach containment and is not a "
            "meaningful operational claim."
        )
    if any(r.get("requires_human_approval") for r in detected):
        caveats.append(
            "At least one recommended containment option requires human "
            "approval before execution, so real-world MTTR would include an "
            "approval wait not captured here."
        )
    payload["caveats"] = caveats
    payload["_trajectories"] = trajectories

    logger.info(
        "evaluation.timing: completed",
        scenarios=len(per_scenario),
        detected=len(detected),
        mttd_minutes=sentinel_mttd,
        detection_coverage=detection_coverage,
    )
    return payload
