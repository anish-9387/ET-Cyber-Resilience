from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple
import hashlib

from app.agents.mitre_mapper import mitre_mapper
from app.agents.threat_prediction_agent import TECHNIQUE_TRANSITION_MATRIX
from app.world_model.attacker_belief import (
    OBJECTIVE_TECHNIQUE_WEIGHTS,
    TACTIC_BASE_ETA_MINUTES,
)
from app.world_model.entity_state import criticality_weight, utcnow
from app.world_model.mission_impact import compute_mission_impact


PRUNE_THRESHOLD = 0.06
MAX_DEPTH = 4
MAX_FUTURES = 5
MIN_FUTURES = 3
MAX_ROOTS = 3
DECEPTION_ATTRACTIVENESS = 0.55
#: P(compromised) at or above which an entity counts as already held by the
#: attacker: it becomes a foothold to forecast *from*, never a target to
#: forecast *towards*.
FOOTHOLD_THRESHOLD = 0.4
#: Tactics that act on assets the attacker already holds. You encrypt or wipe
#: what you control, so for these an owned asset is a legitimate next target;
#: movement, discovery and collection reach for assets not yet held.
HELD_ASSET_TACTICS = {"impact"}
DISTANCE_PENALTY = 0.35
PROJECTED_COMPROMISE_P = 0.85

COLD_START_ROOTS: List[Tuple[str, float]] = [
    ("T1566", 0.45),
    ("T1190", 0.35),
    ("T1078", 0.20),
]

TACTIC_TARGET_TYPES: Dict[str, List[str]] = {
    "initial_access": ["workstation", "server", "user", "network_device"],
    "execution": ["workstation", "server", "user"],
    "persistence": ["server", "workstation", "credential", "user"],
    "privilege_escalation": ["server", "workstation", "credential"],
    "defense_evasion": ["server", "workstation", "application"],
    "credential_access": ["credential", "server", "workstation", "user"],
    "discovery": ["server", "network_device", "database", "workstation"],
    "lateral_movement": ["server", "workstation", "ot_device", "iot_device"],
    "collection": ["database", "server", "workstation"],
    "command_and_control": ["server", "workstation", "network_device"],
    "exfiltration": ["database", "server", "workstation"],
    "impact": ["server", "ot_device", "database", "iot_device", "workstation"],
}

TERMINAL_OBJECTIVE_BY_TACTIC: Dict[str, str] = {
    "impact": "ransom_deployment",
    "exfiltration": "exfiltrate_data",
    "collection": "exfiltrate_data",
    "persistence": "persistence_establishment",
    "credential_access": "persistence_establishment",
    "lateral_movement": "ot_disruption",
    "discovery": "persistence_establishment",
}


def _technique_name(technique_id: str) -> str:
    technique = mitre_mapper.get_technique(technique_id)
    return technique.get("name", technique_id) if technique else technique_id


def _technique_tactic(technique_id: str) -> str:
    technique = mitre_mapper.get_technique(technique_id)
    if not technique:
        return "unknown"
    return technique.get("tactic", "unknown").lower().replace(" ", "_")


def _step_eta(technique_id: str, step_index: int) -> int:
    tactic = _technique_tactic(technique_id)
    return TACTIC_BASE_ETA_MINUTES.get(tactic, 20) + (step_index * 4)


def _anchor_entities(model: Any) -> List[str]:
    compromised = [
        entity.id for entity in model.all_entities() if entity.p_compromised >= FOOTHOLD_THRESHOLD
    ]
    if compromised:
        return compromised
    exposed = [
        entity.id
        for entity in model.all_entities()
        if entity.attributes.get("internet_facing")
    ]
    return exposed or [entity.id for entity in model.all_entities()[:1]]


def distance_map(model: Any, anchors: List[str]) -> Dict[str, int]:
    from collections import deque

    distances: Dict[str, int] = {anchor: 0 for anchor in anchors if model.get_entity(anchor)}
    frontier = deque(sorted(distances))
    while frontier:
        current = frontier.popleft()
        for neighbor_id, _relation_type, _direction in sorted(model.adjacency.get(current, [])):
            if neighbor_id in distances:
                continue
            distances[neighbor_id] = distances[current] + 1
            frontier.append(neighbor_id)
    return distances


def select_target(
    model: Any,
    technique_id: str,
    distances: Dict[str, int],
    already_targeted: List[str],
) -> Optional[Dict[str, Any]]:
    tactic = _technique_tactic(technique_id)
    preferred_types = TACTIC_TARGET_TYPES.get(tactic, ["server"])

    best: Optional[Tuple[float, str, Dict[str, Any]]] = None
    for entity in model.all_entities():
        if entity.id in already_targeted:
            continue
        if entity.isolated:
            continue
        # Outside the impact tactics, an asset the attacker already holds is a
        # foothold rather than a forecast target. Allowing them everywhere
        # pinned every step at hop 0 and saturated attack_success at 1.0, which
        # in turn made every candidate response show a zero reduction.
        if (
            tactic not in HELD_ASSET_TACTICS
            and entity.p_compromised >= FOOTHOLD_THRESHOLD
            and not entity.is_deception
        ):
            continue
        if entity.entity_type not in preferred_types:
            continue
        distance = distances.get(entity.id)
        if distance is None:
            continue
        score = criticality_weight(entity.criticality)
        score += DECEPTION_ATTRACTIVENESS if entity.is_deception else 0.0
        score += entity.p_compromised * 0.3
        score -= DISTANCE_PENALTY * distance
        type_rank = preferred_types.index(entity.entity_type)
        score -= type_rank * 0.05
        payload = {
            "target_entity": entity.id,
            "target_name": entity.name,
            "target_type": entity.entity_type,
            "target_criticality": entity.criticality,
            "hops_from_foothold": distance,
            "selection_score": round(score, 4),
            "is_deception": entity.is_deception,
        }
        if best is None or score > best[0] or (score == best[0] and entity.id < best[1]):
            best = (score, entity.id, payload)
    return best[2] if best else None


def _expand_tree(roots: List[Tuple[str, float]]) -> List[Dict[str, Any]]:
    leaves: List[Dict[str, Any]] = []
    frontier: List[Dict[str, Any]] = [
        {"path": [technique_id], "probability": probability} for technique_id, probability in roots
    ]

    while frontier:
        node = frontier.pop(0)
        path = node["path"]
        probability = node["probability"]
        successors = TECHNIQUE_TRANSITION_MATRIX.get(path[-1], [])
        expandable = [
            (technique_id, transition)
            for technique_id, transition in successors
            if technique_id not in path and probability * transition >= PRUNE_THRESHOLD
        ]
        if not expandable or len(path) >= MAX_DEPTH:
            leaves.append({"path": path, "probability": probability})
            continue
        for technique_id, transition in sorted(expandable, key=lambda item: (-item[1], item[0])):
            frontier.append(
                {"path": path + [technique_id], "probability": probability * transition}
            )
    return leaves


def _access_factor(model: Any, technique_id: str, target: Dict[str, Any]) -> float:
    """How firmly the attacker holds the asset a held-asset tactic acts on.

    Encrypting or wiping a host needs code execution on it, so the feasibility
    of an impact step scales with the model's belief that the attacker already
    controls the target. Without this, every 'critical' asset at hop 0 scored an
    identical 1.0, so containing one simply handed the attacker an equally good
    substitute and no intervention could ever show a reduction.
    """
    if _technique_tactic(technique_id) not in HELD_ASSET_TACTICS:
        return 1.0
    entity = model.get_entity(target["target_entity"])
    if entity is None or entity.is_deception:
        return 1.0
    return entity.p_compromised


def _roots_from_observed(observed: List[str]) -> List[Tuple[str, float]]:
    """Seed the forecast tree from the attacker's most recent positions.

    Rooting solely at the single last observed technique collapses the forecast
    whenever that technique is terminal in the transition matrix (T1486 and
    T1490 have no successors), which yields exactly one degenerate future. An
    attacker mid-campaign holds several live positions, so the last MAX_ROOTS
    distinct techniques each seed a branch, weighted harmonically by recency
    (most recent 1, then 1/2, 1/3) and normalised to sum to 1.
    """
    recent = list(dict.fromkeys(reversed(observed)))[:MAX_ROOTS]
    weighted = [(technique_id, 1.0 / (index + 1)) for index, technique_id in enumerate(recent)]
    total = sum(weight for _technique_id, weight in weighted)
    if total <= 0:
        return []
    return [(technique_id, weight / total) for technique_id, weight in weighted]


def _terminal_objective(technique_id: str) -> str:
    best_objective = None
    best_weight = 0.0
    for objective, weights in OBJECTIVE_TECHNIQUE_WEIGHTS.items():
        weight = weights.get(technique_id, 0.0)
        if weight > best_weight or (weight == best_weight and weight > 0 and objective < (best_objective or "~")):
            best_weight = weight
            best_objective = objective
    if best_objective:
        return best_objective
    return TERMINAL_OBJECTIVE_BY_TACTIC.get(_technique_tactic(technique_id), "persistence_establishment")


def _future_id(path: List[str]) -> str:
    digest = hashlib.sha1("->".join(path).encode("utf-8")).hexdigest()[:10]
    return f"future-{digest}"


def _future_name(path: List[str], objective: str) -> str:
    return f"{objective.replace('_', ' ').title()} via {' -> '.join(path)}"


def _projected_mission_impact(
    model: Any,
    target_ids: List[str],
    baseline: Dict[str, Any],
) -> Dict[str, Any]:
    if not target_ids:
        return {
            "overall_mission_risk": baseline["overall_mission_risk"],
            "delta": 0.0,
            "population_affected": baseline["population_affected_total"],
            "highest_safety_risk": baseline["highest_safety_risk"],
            "degraded_functions": [],
            "basis": "no reachable target entities on this path",
        }
    projected = compute_mission_impact(
        model, {entity_id: PROJECTED_COMPROMISE_P for entity_id in target_ids}
    )
    return {
        "overall_mission_risk": projected["overall_mission_risk"],
        "delta": round(projected["overall_mission_risk"] - baseline["overall_mission_risk"], 6),
        "population_affected": projected["population_affected_total"],
        "highest_safety_risk": projected["highest_safety_risk"],
        "degraded_functions": [
            {
                "name": function["name"],
                "availability": function["availability"],
                "safety_risk": function["safety_risk"],
            }
            for function in projected["functions"]
            if function["degradation"] >= 0.2
        ],
        "basis": f"projected P(compromised) = {PROJECTED_COMPROMISE_P} on forecast target entities",
    }


def _path_confidence(model: Any, steps: List[Dict[str, Any]], depth: int, cold_start: bool) -> float:
    confidences = []
    for step in steps:
        entity = model.get_entity(step.get("target_entity") or "")
        if entity is not None:
            confidences.append(entity.confidence)
    evidence_confidence = sum(confidences) / len(confidences) if confidences else 0.0
    depth_factor = 0.9 ** max(depth - 1, 0)
    base = 0.15 if cold_start else 0.35
    return round(min((base + 0.65 * evidence_confidence) * depth_factor, 0.99), 4)


def generate_futures(model: Any, horizon_minutes: int = 60) -> Dict[str, Any]:
    observed = model.observed_techniques()
    cold_start = not observed

    if cold_start:
        roots = list(COLD_START_ROOTS)
        basis = "cold_start_base_rates"
        root_note = (
            "No attacker techniques observed yet; futures are generated from documented "
            "initial-access base rates rather than live evidence."
        )
    else:
        roots = _roots_from_observed(observed)
        basis = "observed_technique_chain"
        root_note = (
            "Rooted at the attacker's most recent observed positions "
            + ", ".join(f"{technique_id} (weight {weight:.3f})" for technique_id, weight in roots)
            + "; weights are recency-harmonic and normalised."
        )

    leaves = _expand_tree(roots)
    leaves.sort(key=lambda leaf: (-leaf["probability"], "->".join(leaf["path"])))

    deduped: List[Dict[str, Any]] = []
    seen_signatures = set()
    for leaf in leaves:
        signature = "->".join(leaf["path"])
        if signature in seen_signatures:
            continue
        seen_signatures.add(signature)
        deduped.append(leaf)

    selected = deduped[:MAX_FUTURES]
    total_probability = sum(leaf["probability"] for leaf in selected)
    anchors = _anchor_entities(model)
    distances = distance_map(model, anchors)
    baseline_mission = compute_mission_impact(model)

    futures: List[Dict[str, Any]] = []
    for leaf in selected:
        path = leaf["path"] if cold_start else leaf["path"][1:] or leaf["path"]
        already_targeted: List[str] = []
        steps: List[Dict[str, Any]] = []
        cumulative_eta = 0
        step_feasibilities: List[float] = []

        for index, technique_id in enumerate(path):
            cumulative_eta += _step_eta(technique_id, index)
            target = select_target(model, technique_id, distances, already_targeted)
            if target:
                already_targeted.append(target["target_entity"])
                step_feasibility = round(
                    criticality_weight(target["target_criticality"])
                    * _access_factor(model, technique_id, target)
                    / (1.0 + target["hops_from_foothold"]),
                    6,
                )
            else:
                step_feasibility = 0.0
            step_feasibilities.append(step_feasibility)
            steps.append(
                {
                    "technique_id": technique_id,
                    "name": _technique_name(technique_id),
                    "tactic": _technique_tactic(technique_id),
                    "target_entity": target["target_entity"] if target else None,
                    "target_name": target["target_name"] if target else None,
                    "target_type": target["target_type"] if target else None,
                    "hops_from_foothold": target["hops_from_foothold"] if target else None,
                    "step_feasibility": step_feasibility,
                    "routes_through_deception": bool(target and target["is_deception"]),
                    "eta_minutes": cumulative_eta,
                    "within_horizon": cumulative_eta <= horizon_minutes,
                    "unreachable_reason": (
                        None
                        if target
                        else "no reachable, not-yet-compromised entity of a compatible type"
                    ),
                }
            )

        feasibility = (
            round(sum(step_feasibilities) / len(step_feasibilities), 6) if step_feasibilities else 0.0
        )
        raw_probability = leaf["probability"] / total_probability if total_probability > 0 else 0.0
        probability = round(raw_probability, 4)
        terminal_objective = _terminal_objective(path[-1])
        target_ids = [step["target_entity"] for step in steps if step["target_entity"]]

        futures.append(
            {
                "id": _future_id(leaf["path"]),
                "name": _future_name(path, terminal_objective),
                "probability": probability,
                "normalized_probability_exact": raw_probability,
                "raw_tree_probability": round(leaf["probability"], 6),
                "feasibility": feasibility,
                "path": steps,
                "terminal_objective": terminal_objective,
                "terminal_technique": path[-1],
                "eta_minutes": steps[-1]["eta_minutes"] if steps else 0,
                "within_horizon": bool(steps and steps[-1]["eta_minutes"] <= horizon_minutes),
                "mission_impact": _projected_mission_impact(model, target_ids, baseline_mission),
                "confidence": _path_confidence(model, steps, len(path), cold_start),
                "routes_through_deception": any(step["routes_through_deception"] for step in steps),
                "target_entities": target_ids,
            }
        )

    futures.sort(key=lambda item: (-item["probability"], item["id"]))
    attack_success = round(
        min(
            max(
                sum(
                    future["normalized_probability_exact"] * future["feasibility"]
                    for future in futures
                ),
                0.0,
            ),
            1.0,
        ),
        6,
    )

    return {
        "generated_at": utcnow().isoformat(),
        "snapshot_id": model.snapshot_id(),
        "horizon_minutes": horizon_minutes,
        "basis": basis,
        "root_note": root_note,
        "observed_techniques": observed,
        "anchors": anchors,
        "future_count": len(futures),
        "minimum_expected_futures": MIN_FUTURES,
        "prune_threshold": PRUNE_THRESHOLD,
        "attack_success": attack_success,
        "attack_success_definition": (
            "sum over futures of normalized branch probability times path feasibility, where a "
            "step's feasibility is criticality_weight(target) times the attacker's access to "
            "that target (P(compromised) for impact tactics, else 1.0) divided by "
            "(1 + hops from the nearest foothold), and 0 when no compatible target is "
            "graph-reachable"
        ),
        "deterministic": True,
        "futures": futures,
    }
