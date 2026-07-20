from __future__ import annotations

from typing import Any, Dict, List, Tuple

from app.agents.mitre_mapper import TACTIC_ORDER, mitre_mapper
from app.agents.threat_prediction_agent import TECHNIQUE_TRANSITION_MATRIX
from app.world_model.entity_state import decay_weight, ensure_aware, severity_weight, utcnow


TACTIC_BASE_ETA_MINUTES: Dict[str, int] = {
    "initial_access": 30,
    "execution": 10,
    "persistence": 12,
    "privilege_escalation": 15,
    "defense_evasion": 8,
    "credential_access": 15,
    "discovery": 12,
    "lateral_movement": 18,
    "collection": 20,
    "command_and_control": 10,
    "exfiltration": 25,
    "impact": 6,
}

OBJECTIVE_TECHNIQUE_WEIGHTS: Dict[str, Dict[str, float]] = {
    "destroy_backups": {
        "T1490": 3.2, "T1485": 2.6, "T1562": 1.1, "T1078": 0.5,
        "T1021": 0.5, "T1003": 0.5, "T1087": 0.3,
    },
    "exfiltrate_data": {
        "T1048": 3.0, "T1567": 3.0, "T1039": 2.2, "T1005": 1.8, "T1020": 2.0,
        "T1114": 1.4, "T1071": 0.8, "T1573": 0.7, "T1046": 0.3,
    },
    "ransom_deployment": {
        "T1486": 3.4, "T1490": 2.0, "T1489": 1.4, "T1562": 1.2, "T1570": 1.0,
        "T1021": 0.8, "T1003": 0.7, "T1078": 0.5,
    },
    "ot_disruption": {
        "T1499": 2.4, "T1485": 1.6, "T1562": 0.9, "T1021": 0.8, "T1046": 0.9,
        "T1135": 0.6, "T1078": 0.6, "T1570": 0.7,
    },
    "persistence_establishment": {
        "T1547": 2.8, "T1053": 2.6, "T1098": 2.4, "T1136": 2.2, "T1505": 2.2,
        "T1078": 1.0, "T1070": 0.6, "T1036": 0.5,
    },
}

OBJECTIVE_TARGET_AFFINITY: Dict[str, Dict[str, float]] = {
    "destroy_backups": {"server": 0.6, "database": 0.5},
    "exfiltrate_data": {"database": 0.8, "server": 0.4, "application": 0.3},
    "ransom_deployment": {"server": 0.6, "database": 0.5, "iot_device": 0.3},
    "ot_disruption": {"ot_device": 1.2, "network_device": 0.4},
    "persistence_establishment": {"user": 0.5, "credential": 0.7, "server": 0.3},
}

OBJECTIVE_DESCRIPTIONS: Dict[str, str] = {
    "destroy_backups": "Eliminate recovery capability before a destructive action",
    "exfiltrate_data": "Stage and remove sensitive patient and identity data",
    "ransom_deployment": "Encrypt clinical systems and extort the hospital",
    "ot_disruption": "Disrupt power, water treatment or life-safety control systems",
    "persistence_establishment": "Establish durable, redundant footholds for long-dwell access",
}

CAMPAIGN_TECHNIQUE_SETS: Dict[str, Dict[str, Any]] = {
    "APT29": {
        "techniques": {"T1566", "T1078", "T1059", "T1547", "T1003", "T1550", "T1021", "T1005", "T1567", "T1071", "T1098"},
        "motivation": "espionage",
        "sectors": ["Government", "Healthcare", "IT"],
    },
    "APT41": {
        "techniques": {"T1190", "T1059", "T1505", "T1068", "T1003", "T1021", "T1570", "T1005", "T1048", "T1036"},
        "motivation": "espionage and financially motivated theft",
        "sectors": ["Government", "Healthcare", "Telecom"],
    },
    "LockBit 3.0": {
        "techniques": {"T1566", "T1078", "T1059", "T1562", "T1003", "T1021", "T1570", "T1490", "T1486", "T1489"},
        "motivation": "financial extortion",
        "sectors": ["Healthcare", "Government", "Manufacturing"],
    },
    "Sandworm": {
        "techniques": {"T1190", "T1059", "T1078", "T1021", "T1046", "T1135", "T1485", "T1499", "T1562", "T1570"},
        "motivation": "destructive state-directed disruption",
        "sectors": ["Energy", "Government", "Critical Infrastructure"],
    },
}

CAPABILITY_TECHNIQUE_MAP: Dict[str, List[str]] = {
    "credential_theft": ["T1003", "T1555", "T1552", "T1056", "T1110"],
    "lateral_movement": ["T1021", "T1550", "T1570", "T1091"],
    "defense_evasion": ["T1562", "T1070", "T1036", "T1055", "T1112"],
    "privilege_escalation": ["T1068", "T1055", "T1548", "T1134"],
    "persistence_engineering": ["T1547", "T1053", "T1098", "T1136", "T1505"],
    "data_staging_and_exfiltration": ["T1005", "T1039", "T1048", "T1567", "T1020", "T1114"],
    "destructive_impact": ["T1486", "T1485", "T1490", "T1499"],
    "discovery_and_mapping": ["T1087", "T1069", "T1082", "T1046", "T1135"],
    "command_and_control": ["T1071", "T1095", "T1573", "T1102"],
}

DESTRUCTIVE_TECHNIQUES = {"T1486", "T1485", "T1490", "T1499", "T1562", "T1070"}
STEALTH_TECHNIQUES = {"T1550", "T1078", "T1036", "T1112", "T1573", "T1102"}


def _technique_name(technique_id: str) -> str:
    technique = mitre_mapper.get_technique(technique_id)
    return technique.get("name", technique_id) if technique else technique_id


def _technique_tactic(technique_id: str) -> str:
    technique = mitre_mapper.get_technique(technique_id)
    if not technique:
        return "unknown"
    return technique.get("tactic", "unknown").lower().replace(" ", "_")


def technique_rarity() -> Dict[str, float]:
    in_degree: Dict[str, int] = {}
    for successors in TECHNIQUE_TRANSITION_MATRIX.values():
        for technique_id, _probability in successors:
            in_degree[technique_id] = in_degree.get(technique_id, 0) + 1
    max_degree = max(in_degree.values()) if in_degree else 1
    rarity: Dict[str, float] = {}
    for technique_id in set(list(TECHNIQUE_TRANSITION_MATRIX.keys()) + list(in_degree.keys())):
        degree = in_degree.get(technique_id, 0)
        rarity[technique_id] = round(1.0 - (degree / max_degree), 4)
    return rarity


def _weighted_technique_events(model: Any) -> List[Dict[str, Any]]:
    now = utcnow()
    events: List[Dict[str, Any]] = []
    for event in model.observed_technique_events():
        timestamp = ensure_aware_iso(event["timestamp"])
        age_hours = max((now - timestamp).total_seconds() / 3600.0, 0.0)
        events.append(
            {
                **event,
                "weight": round(decay_weight(age_hours) * severity_weight(event["severity"]), 6),
            }
        )
    return events


def ensure_aware_iso(value: str):
    from datetime import datetime

    return ensure_aware(datetime.fromisoformat(value))


def score_objectives(model: Any) -> List[Dict[str, Any]]:
    events = _weighted_technique_events(model)
    compromised = [e for e in model.all_entities() if e.p_compromised >= 0.4]

    scored: List[Dict[str, Any]] = []
    for objective, technique_weights in OBJECTIVE_TECHNIQUE_WEIGHTS.items():
        technique_score = 0.0
        contributions: List[Dict[str, Any]] = []
        for event in events:
            weight = technique_weights.get(event["technique_id"])
            if not weight:
                continue
            contribution = weight * event["weight"]
            technique_score += contribution
            contributions.append(
                {
                    "technique_id": event["technique_id"],
                    "technique_name": _technique_name(event["technique_id"]),
                    "entity_id": event["entity_id"],
                    "objective_weight": weight,
                    "recency_severity_weight": event["weight"],
                    "contribution": round(contribution, 4),
                }
            )
        affinity = OBJECTIVE_TARGET_AFFINITY.get(objective, {})
        target_score = 0.0
        target_contributions: List[Dict[str, Any]] = []
        for entity in compromised:
            affinity_weight = affinity.get(entity.entity_type)
            if not affinity_weight:
                continue
            contribution = affinity_weight * entity.p_compromised * entity.risk_weight()
            target_score += contribution
            target_contributions.append(
                {
                    "entity_id": entity.id,
                    "entity_type": entity.entity_type,
                    "p_compromised": round(entity.p_compromised, 4),
                    "contribution": round(contribution, 4),
                }
            )
        scored.append(
            {
                "objective": objective,
                "description": OBJECTIVE_DESCRIPTIONS[objective],
                "technique_score": round(technique_score, 4),
                "target_score": round(target_score, 4),
                "raw_score": round(technique_score + target_score, 4),
                "technique_contributions": sorted(
                    contributions, key=lambda item: (-item["contribution"], item["technique_id"])
                )[:5],
                "target_contributions": sorted(
                    target_contributions, key=lambda item: (-item["contribution"], item["entity_id"])
                )[:5],
            }
        )

    total = sum(item["raw_score"] for item in scored)
    for item in scored:
        item["probability"] = round(item["raw_score"] / total, 4) if total > 0 else 0.0
    return sorted(scored, key=lambda item: (-item["raw_score"], item["objective"]))


def match_campaign(observed: List[str]) -> Dict[str, Any]:
    observed_set = set(observed)
    candidates: List[Dict[str, Any]] = []
    for actor, profile in CAMPAIGN_TECHNIQUE_SETS.items():
        actor_set = profile["techniques"]
        intersection = observed_set & actor_set
        union = observed_set | actor_set
        jaccard = len(intersection) / len(union) if union else 0.0
        candidates.append(
            {
                "actor": actor,
                "confidence": round(jaccard, 4),
                "similarity_metric": "jaccard_technique_set",
                "shared_techniques": sorted(intersection),
                "actor_technique_count": len(actor_set),
                "observed_technique_count": len(observed_set),
                "motivation": profile["motivation"],
                "target_sectors": profile["sectors"],
            }
        )
    candidates.sort(key=lambda item: (-item["confidence"], item["actor"]))
    best = candidates[0]
    return {"best": best, "candidates": candidates}


def assess_sophistication(observed: List[str]) -> Dict[str, Any]:
    rarity = technique_rarity()
    scores = [rarity.get(technique_id, 0.85) for technique_id in observed]
    if not scores:
        return {"label": "unknown", "score": 0.0, "basis": "no techniques observed yet"}
    mean_rarity = sum(scores) / len(scores)
    breadth_bonus = min(len(set(observed)) / 12.0, 1.0) * 0.25
    score = round(min(mean_rarity * 0.75 + breadth_bonus, 1.0), 4)
    if score < 0.3:
        label = "commodity"
    elif score < 0.5:
        label = "moderate"
    elif score < 0.72:
        label = "advanced"
    else:
        label = "advanced_persistent"
    return {
        "label": label,
        "score": score,
        "basis": (
            f"mean transition-matrix rarity {mean_rarity:.3f} over {len(observed)} observed techniques "
            f"plus technique-breadth bonus {breadth_bonus:.3f}"
        ),
    }


def infer_knowledge(model: Any) -> List[Dict[str, Any]]:
    discovered: Dict[str, Dict[str, Any]] = {}
    for entity in model.all_entities():
        direct = [item for item in entity.evidence if not item.derived]
        if not direct:
            continue
        discovered[entity.id] = {
            "entity_id": entity.id,
            "name": entity.name,
            "entity_type": entity.entity_type,
            "basis": "direct_observation",
            "evidence_count": len(direct),
            "p_compromised": round(entity.p_compromised, 4),
        }
    for entity_id in list(discovered.keys()):
        entity = model.get_entity(entity_id)
        if not entity or entity.p_compromised < 0.5:
            continue
        for neighbor in model.neighbors(entity_id):
            if neighbor["id"] in discovered:
                continue
            discovered[neighbor["id"]] = {
                "entity_id": neighbor["id"],
                "name": neighbor["name"],
                "entity_type": neighbor["entity_type"],
                "basis": f"adjacent to compromised {entity.name} via '{neighbor['relation']}'",
                "evidence_count": 0,
                "p_compromised": neighbor["p_compromised"],
            }
    return sorted(discovered.values(), key=lambda item: (-item["p_compromised"], item["entity_id"]))


def derive_capabilities(observed: List[str]) -> List[Dict[str, Any]]:
    capabilities: List[Dict[str, Any]] = []
    observed_set = set(observed)
    for capability, technique_ids in CAPABILITY_TECHNIQUE_MAP.items():
        matched = sorted(observed_set & set(technique_ids))
        if not matched:
            continue
        capabilities.append(
            {
                "capability": capability,
                "demonstrated_by": matched,
                "strength": round(len(matched) / len(technique_ids), 4),
            }
        )
    return sorted(capabilities, key=lambda item: (-item["strength"], item["capability"]))


def _risk_appetite(observed: List[str]) -> Dict[str, Any]:
    if not observed:
        return {"label": "unknown", "score": 0.0, "basis": "no techniques observed"}
    destructive = len([t for t in observed if t in DESTRUCTIVE_TECHNIQUES])
    stealth = len([t for t in observed if t in STEALTH_TECHNIQUES])
    score = round((destructive + 0.5) / (destructive + stealth + 1.0), 4)
    if score < 0.35:
        label = "low_stealth_focused"
    elif score < 0.6:
        label = "moderate"
    else:
        label = "high_destructive"
    return {
        "label": label,
        "score": score,
        "basis": f"{destructive} destructive vs {stealth} stealth techniques observed",
    }


def _persistence_profile(model: Any, observed: List[str]) -> Dict[str, Any]:
    persistence_techniques = sorted(set(observed) & set(CAPABILITY_TECHNIQUE_MAP["persistence_engineering"]))
    footholds = [e for e in model.all_entities() if e.p_compromised >= 0.5]
    score = round(min((len(persistence_techniques) * 0.25) + (len(footholds) * 0.1), 1.0), 4)
    if score < 0.25:
        label = "transient"
    elif score < 0.6:
        label = "established"
    else:
        label = "entrenched"
    return {
        "label": label,
        "score": score,
        "persistence_techniques": persistence_techniques,
        "footholds": [entity.id for entity in footholds],
    }


def _current_tactic(observed: List[str]) -> str:
    best_index = -1
    best_tactic = "unknown"
    for technique_id in observed:
        tactic = _technique_tactic(technique_id)
        if tactic in TACTIC_ORDER:
            index = TACTIC_ORDER.index(tactic)
            if index > best_index:
                best_index = index
                best_tactic = tactic
    return best_tactic


def _eta_for(technique_id: str, probability: float, step: int) -> int:
    tactic = _technique_tactic(technique_id)
    base = TACTIC_BASE_ETA_MINUTES.get(tactic, 20)
    confidence_factor = 1.0 - (probability * 0.4)
    return max(int(round(base * confidence_factor)) + (step * 5), 2)


def predict_next_techniques(observed: List[str], limit: int = 5) -> List[Dict[str, Any]]:
    if not observed:
        return []
    candidate_scores: Dict[str, Tuple[float, str]] = {}
    recency_weights = {
        technique_id: 0.5 + 0.5 * ((index + 1) / len(observed))
        for index, technique_id in enumerate(observed)
    }
    for technique_id in observed:
        for successor, probability in TECHNIQUE_TRANSITION_MATRIX.get(technique_id, []):
            if successor in observed:
                continue
            weighted = probability * recency_weights[technique_id]
            existing = candidate_scores.get(successor)
            if existing is None or weighted > existing[0]:
                candidate_scores[successor] = (weighted, technique_id)

    ranked = sorted(candidate_scores.items(), key=lambda item: (-item[1][0], item[0]))[:limit]
    total = sum(score for _tid, (score, _pred) in ranked)
    results: List[Dict[str, Any]] = []
    for step, (technique_id, (score, predecessor)) in enumerate(ranked):
        probability = round(score / total, 4) if total > 0 else 0.0
        results.append(
            {
                "technique_id": technique_id,
                "name": _technique_name(technique_id),
                "tactic": _technique_tactic(technique_id),
                "probability": probability,
                "raw_transition_score": round(score, 4),
                "eta_minutes": _eta_for(technique_id, probability, step),
                "rationale": (
                    f"Observed {predecessor} ({_technique_name(predecessor)}); the ATT&CK transition "
                    f"matrix gives P({technique_id}|{predecessor}) = "
                    f"{dict(TECHNIQUE_TRANSITION_MATRIX.get(predecessor, [])).get(technique_id, 0.0):.2f}, "
                    f"weighted {score:.3f} by observation recency."
                ),
            }
        )
    return results


def infer_attacker_belief(model: Any) -> Dict[str, Any]:
    observed = model.observed_techniques()
    objectives = score_objectives(model)
    top_objective = objectives[0] if objectives else None
    campaign = match_campaign(observed)
    sophistication = assess_sophistication(observed)

    # Objective inference needs weighted technique evidence to have survived
    # recency decay. Attribution does not: a campaign match is a set-similarity
    # question over which techniques were seen at all, so it is reported
    # whenever any technique has been observed. The reported confidence is the
    # raw computed Jaccard, so a weak match honestly reads as weak.
    has_signal = bool(observed) and (top_objective is not None and top_objective["raw_score"] > 0)
    has_techniques = bool(observed)

    return {
        "current_objective": top_objective["objective"] if has_signal else "unknown",
        "objective_confidence": top_objective["probability"] if has_signal else 0.0,
        "objective_description": top_objective["description"] if has_signal else "No attacker activity observed",
        "objective_ranking": objectives,
        "inferred_knowledge": infer_knowledge(model),
        "capabilities": derive_capabilities(observed),
        "sophistication": sophistication,
        "risk_appetite": _risk_appetite(observed),
        "persistence": _persistence_profile(model, observed),
        "campaign_match": {
            "actor": campaign["best"]["actor"] if has_techniques else "unattributed",
            "confidence": campaign["best"]["confidence"] if has_techniques else 0.0,
            "similarity_metric": "jaccard_technique_set",
            "shared_techniques": campaign["best"]["shared_techniques"] if has_techniques else [],
            "motivation": campaign["best"]["motivation"] if has_techniques else None,
        },
        "campaign_candidates": campaign["candidates"],
        "current_tactic": _current_tactic(observed),
        "observed_techniques": observed,
        "observed_technique_detail": [
            {
                "technique_id": technique_id,
                "name": _technique_name(technique_id),
                "tactic": _technique_tactic(technique_id),
            }
            for technique_id in observed
        ],
        "likely_next": predict_next_techniques(observed),
        "method": "transparent weighted-evidence scoring over decayed MITRE technique observations",
    }
