from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.core.logger import logger
from app.world_model.entity_state import Evidence, utcnow
from app.world_model.forecast import generate_futures
from app.world_model.mission_impact import compute_mission_impact


SUPPORTED_INTERVENTIONS = [
    "disable_service",
    "isolate_entity",
    "block_ip",
    "rotate_credentials",
    "deploy_deception",
    "patch_cve",
]

CONTAINMENT_LIKELIHOOD_RATIO = 0.15
REMEDIATION_LIKELIHOOD_RATIO = 0.40

SERVICE_RELATIONS = {"runs_on", "communicates_with", "grants_access_to", "can_access", "controls", "depends_on"}
NETWORK_RELATIONS = {"connected_to", "communicates_with"}
CREDENTIAL_RELATIONS = {"has_credential", "grants_access_to"}


def _apply_negating_evidence(
    model: Any,
    entity_id: str,
    likelihood_ratio: float,
    source: str,
    description: str,
) -> Optional[Dict[str, Any]]:
    entity = model.get_entity(entity_id)
    if entity is None:
        return None
    timestamp = utcnow()
    evidence = Evidence(
        id=Evidence.make_id(entity_id, source, description, timestamp),
        entity_id=entity_id,
        source=source,
        description=description,
        technique_id=None,
        likelihood_ratio=likelihood_ratio,
        severity="info",
        timestamp=timestamp,
        raw={"counterfactual": True},
    )
    if entity.add_evidence(evidence):
        return entity.recompute(timestamp)
    return None


def apply_intervention(model: Any, intervention: Dict[str, Any]) -> Dict[str, Any]:
    kind = intervention.get("type")
    target = intervention.get("target")
    params = intervention.get("params") or {}
    result: Dict[str, Any] = {
        "type": kind,
        "target": target,
        "params": params,
        "applied": False,
        "severed_relations": [],
        "belief_changes": [],
        "notes": [],
    }

    if kind not in SUPPORTED_INTERVENTIONS:
        result["notes"].append(f"unsupported intervention type '{kind}'")
        return result

    entity = model.get_entity(target) if target else None
    if kind != "deploy_deception" and entity is None:
        result["notes"].append(f"target entity '{target}' not present in world model")
        return result

    if kind == "isolate_entity":
        removed = model.remove_relations_for(target)
        entity.isolated = True
        entity.attributes["isolated_by_counterfactual"] = True
        result["severed_relations"] = [relation.to_dict() for relation in removed]
        delta = _apply_negating_evidence(
            model, target, CONTAINMENT_LIKELIHOOD_RATIO,
            "counterfactual.isolate_entity",
            f"{entity.name} network-isolated; attacker can no longer pivot through it",
        )
        if delta:
            result["belief_changes"].append({"entity_id": target, **delta})
        result["applied"] = True
        result["notes"].append(f"all {len(removed)} graph relations touching {target} severed")

    elif kind == "disable_service":
        removed = model.remove_relations_for(target, SERVICE_RELATIONS)
        entity.attributes["service_disabled"] = True
        entity.isolated = True
        result["severed_relations"] = [relation.to_dict() for relation in removed]
        delta = _apply_negating_evidence(
            model, target, CONTAINMENT_LIKELIHOOD_RATIO,
            "counterfactual.disable_service",
            f"Service on {entity.name} stopped; dependent and trust relations removed",
        )
        if delta:
            result["belief_changes"].append({"entity_id": target, **delta})
        result["applied"] = True
        result["notes"].append(f"{len(removed)} service/trust relations severed")

    elif kind == "block_ip":
        removed = model.remove_relations_for(target, NETWORK_RELATIONS)
        entity.attributes["network_blocked"] = True
        entity.attributes["internet_facing"] = False
        result["severed_relations"] = [relation.to_dict() for relation in removed]
        delta = _apply_negating_evidence(
            model, target, REMEDIATION_LIKELIHOOD_RATIO,
            "counterfactual.block_ip",
            f"Egress/ingress blocked for {entity.name} ({entity.attributes.get('ip', 'unknown ip')})",
        )
        if delta:
            result["belief_changes"].append({"entity_id": target, **delta})
        result["applied"] = True
        result["notes"].append(f"{len(removed)} network adjacencies severed")

    elif kind == "rotate_credentials":
        removed = model.remove_relations_for(target, CREDENTIAL_RELATIONS)
        entity.attributes["last_rotated"] = utcnow().date().isoformat()
        entity.attributes["strength"] = "strong"
        result["severed_relations"] = [relation.to_dict() for relation in removed]
        delta = _apply_negating_evidence(
            model, target, CONTAINMENT_LIKELIHOOD_RATIO,
            "counterfactual.rotate_credentials",
            f"{entity.name} rotated; any stolen material is now invalid",
        )
        if delta:
            result["belief_changes"].append({"entity_id": target, **delta})
        for relation in removed:
            other = relation.target if relation.source == target else relation.source
            sibling_delta = _apply_negating_evidence(
                model, other, REMEDIATION_LIKELIHOOD_RATIO,
                "counterfactual.rotate_credentials",
                f"Credential path to {other} invalidated by rotation of {entity.name}",
            )
            if sibling_delta:
                result["belief_changes"].append({"entity_id": other, **sibling_delta})
        result["applied"] = True
        result["notes"].append("credential grants revoked and downstream trust reduced")

    elif kind == "deploy_deception":
        from app.world_model.deception import deploy_asset

        asset = deploy_asset(
            model,
            asset_type=params.get("asset_type", "fake_credentials"),
            near_entity=target or params.get("near_entity"),
            simulated=True,
        )
        result["applied"] = asset.get("deployed", False)
        result["notes"].append(asset.get("note", ""))
        result["deception_asset"] = asset

    elif kind == "patch_cve":
        cve = params.get("cve")
        cves = list(entity.attributes.get("cves", []))
        if cve and cve in cves:
            cves.remove(cve)
            result["notes"].append(f"{cve} patched on {entity.name}")
        elif cves:
            result["notes"].append(f"all {len(cves)} known CVEs patched on {entity.name}")
            cves = []
        else:
            result["notes"].append(f"{entity.name} had no known CVEs; patching is a no-op")
        entity.attributes["cves"] = cves
        entity.prior = max(entity.prior - 0.01 * (1 if cve else 2), 0.005)
        delta = _apply_negating_evidence(
            model, target, REMEDIATION_LIKELIHOOD_RATIO,
            "counterfactual.patch_cve",
            f"Exploitable surface reduced on {entity.name}",
        )
        if delta:
            result["belief_changes"].append({"entity_id": target, **delta})
        result["applied"] = True

    return result


def _index_futures(futures: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    return {future["id"]: future for future in futures}


def _severed_paths(
    baseline_futures: List[Dict[str, Any]],
    counterfactual_futures: Dict[str, Dict[str, Any]],
) -> List[Dict[str, Any]]:
    severed: List[Dict[str, Any]] = []
    for future in baseline_futures:
        after = counterfactual_futures.get(future["id"])
        broken_steps: List[Dict[str, Any]] = []
        for index, step in enumerate(future["path"]):
            after_step = after["path"][index] if after and index < len(after["path"]) else None
            before_target = step.get("target_entity")
            after_target = after_step.get("target_entity") if after_step else None
            if before_target and before_target != after_target:
                broken_steps.append(
                    {
                        "technique_id": step["technique_id"],
                        "previous_target": before_target,
                        "previous_target_name": step.get("target_name"),
                        "new_target": after_target,
                        "reason": (
                            "target no longer graph-reachable from any foothold"
                            if after_target is None
                            else "attacker forced onto a different, less valuable target"
                        ),
                    }
                )
        if broken_steps:
            severed.append(
                {
                    "future_id": future["id"],
                    "future_name": future["name"],
                    "terminal_objective": future["terminal_objective"],
                    "baseline_probability": future["probability"],
                    "counterfactual_probability": after["probability"] if after else 0.0,
                    "baseline_feasibility": future["feasibility"],
                    "counterfactual_feasibility": after["feasibility"] if after else 0.0,
                    "severed_steps": broken_steps,
                }
            )
    return severed


def evaluate_counterfactual(
    model: Any,
    interventions: List[Dict[str, Any]],
    horizon_minutes: int = 60,
) -> Dict[str, Any]:
    baseline_forecast = generate_futures(model, horizon_minutes)
    baseline_mission = compute_mission_impact(model)

    sandbox = model.clone()
    applied: List[Dict[str, Any]] = []
    for intervention in interventions:
        try:
            applied.append(apply_intervention(sandbox, intervention))
        except Exception as exc:
            logger.warning(
                "counterfactual_intervention_failed",
                intervention=intervention,
                error=str(exc),
            )
            applied.append({**intervention, "applied": False, "notes": [f"error: {exc}"]})

    counterfactual_forecast = generate_futures(sandbox, horizon_minutes)
    counterfactual_mission = compute_mission_impact(sandbox)

    baseline_success = baseline_forecast["attack_success"]
    counterfactual_success = counterfactual_forecast["attack_success"]
    after_index = _index_futures(counterfactual_forecast["futures"])

    per_future: List[Dict[str, Any]] = []
    for future in baseline_forecast["futures"]:
        after = after_index.get(future["id"])
        per_future.append(
            {
                "future_id": future["id"],
                "name": future["name"],
                "terminal_objective": future["terminal_objective"],
                "baseline_probability": future["probability"],
                "counterfactual_probability": after["probability"] if after else 0.0,
                "baseline_feasibility": future["feasibility"],
                "counterfactual_feasibility": after["feasibility"] if after else 0.0,
                "baseline_mission_risk": future["mission_impact"]["overall_mission_risk"],
                "counterfactual_mission_risk": (
                    after["mission_impact"]["overall_mission_risk"] if after else None
                ),
                "eliminated": after is None,
            }
        )

    severed = _severed_paths(baseline_forecast["futures"], after_index)
    mission_delta = round(
        counterfactual_mission["overall_mission_risk"] - baseline_mission["overall_mission_risk"], 6
    )
    delta = round(counterfactual_success - baseline_success, 6)

    severed_summary = "; ".join(
        f"{item['future_name']} lost {len(item['severed_steps'])} reachable step(s)"
        for item in severed
    ) or "no attack path was severed"

    intervention_summary = "; ".join(
        f"{item.get('type')} on {item.get('target')} ({'applied' if item.get('applied') else 'not applied'})"
        for item in applied
    ) or "no interventions supplied"

    return {
        "generated_at": utcnow().isoformat(),
        "mode": "simulated",
        "integration": "none",
        "deterministic": True,
        "horizon_minutes": horizon_minutes,
        "interventions": applied,
        "baseline_attack_success": baseline_success,
        "counterfactual_attack_success": counterfactual_success,
        "delta": delta,
        "attack_success_reduction": round(max(baseline_success - counterfactual_success, 0.0), 6),
        "per_future": per_future,
        "severed_paths": severed,
        "baseline_mission_risk": baseline_mission["overall_mission_risk"],
        "counterfactual_mission_risk": counterfactual_mission["overall_mission_risk"],
        "mission_impact_delta": mission_delta,
        "mission_functions_after": [
            {
                "name": function["name"],
                "availability": function["availability"],
                "safety_risk": function["safety_risk"],
            }
            for function in counterfactual_mission["functions"]
        ],
        "explanation": (
            f"Applied {intervention_summary}. Attack success moved from {baseline_success:.4f} to "
            f"{counterfactual_success:.4f} (delta {delta:+.4f}). Mission risk moved from "
            f"{baseline_mission['overall_mission_risk']:.4f} to "
            f"{counterfactual_mission['overall_mission_risk']:.4f} (delta {mission_delta:+.4f}). "
            f"Path analysis: {severed_summary}."
        ),
    }
