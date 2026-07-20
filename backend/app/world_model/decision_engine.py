from __future__ import annotations

from typing import Any, Dict, List, Optional
import hashlib

from app.agents.response_playbooks import (
    PLAYBOOK_REGISTRY,
    ApprovalLevel,
    Playbook,
    RiskLevel,
)
from app.core.config import settings
from app.core.logger import logger
from app.world_model.audit import audit
from app.world_model.counterfactual import evaluate_counterfactual
from app.world_model.entity_state import utcnow


PLAYBOOK_INTERVENTIONS: Dict[str, Dict[str, Any]] = {
    "quarantine_host": {
        "intervention": "isolate_entity",
        "target_types": ["server", "iot_device", "ot_device"],
        "recovery_cost": 0.55,
        "blast_radius_scope": "single_host_and_its_dependents",
    },
    "network_isolation": {
        "intervention": "isolate_entity",
        "target_types": ["network_device"],
        "recovery_cost": 0.85,
        "blast_radius_scope": "entire_network_segment",
    },
    "block_ip": {
        "intervention": "block_ip",
        "target_types": ["server", "network_device"],
        "recovery_cost": 0.20,
        "blast_radius_scope": "north_south_traffic_for_one_host",
    },
    "disable_account": {
        "intervention": "disable_service",
        "target_types": ["user"],
        "recovery_cost": 0.35,
        "blast_radius_scope": "one_identity_and_its_sessions",
    },
    "rotate_credentials": {
        "intervention": "rotate_credentials",
        "target_types": ["credential"],
        "recovery_cost": 0.30,
        "blast_radius_scope": "all_services_bound_to_the_secret",
    },
    "kill_process": {
        "intervention": "disable_service",
        "target_types": ["application", "server"],
        "recovery_cost": 0.25,
        "blast_radius_scope": "one_process_tree",
    },
    "snapshot_vm": {
        "intervention": None,
        "target_types": ["server"],
        "recovery_cost": 0.10,
        "blast_radius_scope": "none_forensic_only",
    },
    "notify_soc": {
        "intervention": None,
        "target_types": [],
        "recovery_cost": 0.02,
        "blast_radius_scope": "none_notification_only",
    },
}

SCORE_WEIGHTS = {
    "attack_success_reduction": 0.60,
    "mission_impact": 0.25,
    "recovery_cost": 0.15,
}

RISK_ORDER = {
    RiskLevel.GREEN: 0,
    RiskLevel.YELLOW: 1,
    RiskLevel.ORANGE: 2,
    RiskLevel.RED: 3,
}


def _option_id(playbook_name: str, target: str) -> str:
    digest = hashlib.sha1(f"{playbook_name}|{target}".encode("utf-8")).hexdigest()[:8]
    return f"opt-{playbook_name}-{digest}"


def _execution_id(option_id: str, ordinal: int) -> str:
    digest = hashlib.sha1(f"{option_id}|{ordinal}".encode("utf-8")).hexdigest()[:8]
    return f"exec-{ordinal:04d}-{digest}"


class DecisionEngine:
    def __init__(self) -> None:
        self._options: Dict[str, Dict[str, Any]] = {}
        self._executions: Dict[str, Dict[str, Any]] = {}
        self._restore_points: Dict[str, Any] = {}
        self._execution_counter = 0

    @property
    def model(self) -> Any:
        from app.world_model.model import world_model

        return world_model

    def _select_target(self, model: Any, target_types: List[str]) -> Optional[Any]:
        if not target_types:
            return None
        candidates = [
            entity
            for entity in model.all_entities()
            if entity.entity_type in target_types and not entity.isolated and not entity.is_deception
        ]
        if not candidates:
            return None
        candidates.sort(key=lambda entity: (-entity.p_compromised, -entity.risk_weight(), entity.id))
        return candidates[0]

    def _approval_required(self, playbook: Playbook) -> bool:
        if not settings.HUMAN_APPROVAL_REQUIRED:
            return False
        return playbook.approval_level in {ApprovalLevel.ASK_APPROVAL, ApprovalLevel.IMMEDIATE}

    def _build_option(self, model: Any, playbook: Playbook, horizon_minutes: int) -> Optional[Dict[str, Any]]:
        mapping = PLAYBOOK_INTERVENTIONS.get(playbook.name)
        if mapping is None:
            return None

        target_entity = self._select_target(model, mapping["target_types"])
        target_id = target_entity.id if target_entity else "soc_queue"
        target_name = target_entity.name if target_entity else "SOC ticket queue"

        if mapping["intervention"] and target_entity is not None:
            counterfactual = evaluate_counterfactual(
                model,
                [{"type": mapping["intervention"], "target": target_id, "params": {}}],
                horizon_minutes,
            )
            attack_success_after = counterfactual["counterfactual_attack_success"]
            baseline = counterfactual["baseline_attack_success"]
            reduction = counterfactual["attack_success_reduction"]
            mission_delta = counterfactual["mission_impact_delta"]
            severed = counterfactual["severed_paths"]
            explanation = counterfactual["explanation"]
            blast_radius_entities = sorted(
                {
                    relation["source"] if relation["source"] != target_id else relation["target"]
                    for item in counterfactual["interventions"]
                    for relation in item.get("severed_relations", [])
                }
            )
        else:
            from app.world_model.forecast import generate_futures

            baseline_forecast = generate_futures(model, horizon_minutes)
            baseline = baseline_forecast["attack_success"]
            attack_success_after = baseline
            reduction = 0.0
            mission_delta = 0.0
            severed = []
            blast_radius_entities = []
            explanation = (
                f"'{playbook.name}' is a non-containment playbook; it produces no change in modelled "
                f"attack success. It is retained as a candidate for evidence preservation and escalation."
            )

        recovery_cost = mapping["recovery_cost"]
        score = round(
            SCORE_WEIGHTS["attack_success_reduction"] * reduction
            - SCORE_WEIGHTS["mission_impact"] * max(mission_delta, 0.0)
            - SCORE_WEIGHTS["recovery_cost"] * recovery_cost,
            6,
        )
        reversible = any(step.requires_rollback for step in playbook.steps)

        return {
            "id": _option_id(playbook.name, target_id),
            "action": playbook.name,
            "playbook": playbook.name,
            "description": playbook.description,
            "target": target_id,
            "target_name": target_name,
            "intervention": mapping["intervention"],
            "baseline_attack_success": baseline,
            "attack_success_after": attack_success_after,
            "attack_success_reduction": reduction,
            "mission_impact": mission_delta,
            "recovery_cost": recovery_cost,
            "blast_radius": {
                "scope": mapping["blast_radius_scope"],
                "affected_entities": blast_radius_entities,
                "affected_entity_count": len(blast_radius_entities),
            },
            "risk_level": playbook.risk_level.value,
            "approval_level": playbook.approval_level.value,
            "approval_required": self._approval_required(playbook),
            "reversible": reversible,
            "rollback": {
                "available": reversible,
                "steps": [
                    {"order": step.order, "command": step.rollback_command}
                    for step in playbook.steps
                    if step.requires_rollback
                ],
            },
            "owner_team": playbook.owner_team,
            "prerequisites": list(playbook.prerequisites),
            "severed_paths": severed,
            "rationale": explanation,
            "score": score,
            "score_formula": (
                f"{SCORE_WEIGHTS['attack_success_reduction']}*attack_success_reduction "
                f"- {SCORE_WEIGHTS['mission_impact']}*max(mission_impact_delta, 0) "
                f"- {SCORE_WEIGHTS['recovery_cost']}*recovery_cost"
            ),
        }

    def options(self, horizon_minutes: int = 60) -> Dict[str, Any]:
        model = self.model
        evidence = model.evidence_summary(limit=5)
        attacker = model.attacker_belief()

        built: List[Dict[str, Any]] = []
        for name in sorted(PLAYBOOK_REGISTRY):
            playbook = PLAYBOOK_REGISTRY[name]
            option = self._build_option(model, playbook, horizon_minutes)
            if option:
                built.append(option)

        built.sort(key=lambda option: (-option["score"], RISK_ORDER.get(RiskLevel(option["risk_level"]), 9), option["id"]))

        for index, option in enumerate(built):
            option["rank"] = index + 1
            option["evidence"] = evidence
            option["attacker_objective"] = attacker["current_objective"]
            option["alternatives_considered"] = [
                {
                    "id": other["id"],
                    "action": other["action"],
                    "target": other["target"],
                    "score": other["score"],
                    "attack_success_reduction": other["attack_success_reduction"],
                    "mission_impact": other["mission_impact"],
                    "why_not_chosen": (
                        f"score {other['score']:.4f} < {option['score']:.4f}"
                        if other["score"] < option["score"]
                        else f"score {other['score']:.4f} >= {option['score']:.4f}"
                    ),
                }
                for other in built
                if other["id"] != option["id"]
            ]

        self._options = {option["id"]: option for option in built}
        recommended = built[0] if built else None

        if recommended:
            audit.record(
                actor="decision_engine",
                actor_type="ai_agent",
                action="rank_response_options",
                target=recommended["target"],
                decision=f"recommend '{recommended['action']}' on {recommended['target']}",
                confidence=attacker.get("objective_confidence", 0.0),
                evidence=evidence,
                reasoning=recommended["rationale"],
                alternatives_considered=recommended["alternatives_considered"],
                rollback_available=recommended["reversible"],
                outcome="options_generated",
            )

        return {
            "generated_at": utcnow().isoformat(),
            "snapshot_id": model.snapshot_id(),
            "mode": "simulated",
            "integration": "none",
            "horizon_minutes": horizon_minutes,
            "objective": (
                "maximize attack_success_reduction while minimizing mission impact and recovery cost"
            ),
            "score_weights": SCORE_WEIGHTS,
            "human_approval_required_globally": settings.HUMAN_APPROVAL_REQUIRED,
            "options": built,
            "recommended_id": recommended["id"] if recommended else None,
        }

    def get_option(self, option_id: str) -> Optional[Dict[str, Any]]:
        if option_id not in self._options:
            self.options()
        return self._options.get(option_id)

    def _simulate_steps(self, option: Dict[str, Any]) -> List[Dict[str, Any]]:
        playbook = PLAYBOOK_REGISTRY.get(option["action"])
        if playbook is None:
            return []
        steps: List[Dict[str, Any]] = []
        for step in playbook.steps:
            steps.append(
                {
                    "order": step.order,
                    "action": step.action,
                    "description": step.description,
                    "command": step.command,
                    "resolved_target": option["target"],
                    "mode": "simulated",
                    "integration": "none",
                    "status": "simulated_ok",
                    "note": (
                        "No external system was contacted. This step was evaluated against the "
                        "in-memory world model only."
                    ),
                    "rollback_command": step.rollback_command if step.requires_rollback else None,
                    "reversible": step.requires_rollback,
                }
            )
        return steps

    def _apply_to_world_model(self, option: Dict[str, Any], execution_id: str) -> Dict[str, Any]:
        from app.world_model.counterfactual import apply_intervention

        model = self.model
        if not option["intervention"]:
            return {"world_model_applied": False, "reason": "playbook has no modelled intervention"}
        self._restore_points[execution_id] = model.clone()
        result = apply_intervention(
            model,
            {"type": option["intervention"], "target": option["target"], "params": {}},
        )
        return {"world_model_applied": result.get("applied", False), "detail": result}

    def execute(self, option_id: str, approved_by: Optional[str] = None) -> Dict[str, Any]:
        option = self.get_option(option_id)
        if option is None:
            return {"error": "option_not_found", "option_id": option_id}

        self._execution_counter += 1
        execution_id = _execution_id(option_id, self._execution_counter)
        needs_approval = option["approval_required"] and not approved_by

        record: Dict[str, Any] = {
            "execution_id": execution_id,
            "option_id": option_id,
            "action": option["action"],
            "target": option["target"],
            "target_name": option["target_name"],
            "requested_at": utcnow().isoformat(),
            "approved_by": approved_by,
            "approval_required": option["approval_required"],
            "approval_level": option["approval_level"],
            "risk_level": option["risk_level"],
            "mode": "simulated",
            "integration": "none",
            "reversible": option["reversible"],
            "rationale": option["rationale"],
            "steps": [],
            "world_model_effect": None,
            "rejection_reason": None,
        }

        if needs_approval:
            record["status"] = "pending_approval"
            record["steps"] = [
                {
                    **step,
                    "status": "not_started",
                    "note": "Held pending human approval; nothing has been evaluated or applied.",
                }
                for step in self._simulate_steps(option)
            ]
            outcome = "held_for_human_approval"
        else:
            record["status"] = "executed"
            record["steps"] = self._simulate_steps(option)
            record["world_model_effect"] = self._apply_to_world_model(option, execution_id)
            record["completed_at"] = utcnow().isoformat()
            outcome = "simulated_execution_complete"

        audit_entry = audit.record(
            actor="decision_engine",
            actor_type="ai_agent" if not approved_by else "human",
            action="execute_response" if not needs_approval else "request_approval",
            target=option["target"],
            decision=f"{option['action']} on {option['target']} (mode=simulated, integration=none)",
            confidence=option["score"],
            evidence=option.get("evidence", []),
            reasoning=option["rationale"],
            alternatives_considered=option.get("alternatives_considered", []),
            approved_by=approved_by,
            rollback_available=option["reversible"],
            outcome=outcome,
        )
        record["audit_id"] = audit_entry["id"]
        self._executions[execution_id] = record
        logger.info(
            "decision_execution",
            execution_id=execution_id,
            option_id=option_id,
            status=record["status"],
            mode="simulated",
        )
        return record

    def pending_approvals(self) -> List[Dict[str, Any]]:
        return [
            record
            for record in self._executions.values()
            if record["status"] == "pending_approval"
        ]

    def approve(
        self,
        execution_id: str,
        approved_by: str,
        decision: str = "approve",
        reason: str = "",
    ) -> Dict[str, Any]:
        record = self._executions.get(execution_id)
        if record is None:
            return {"error": "execution_not_found", "execution_id": execution_id}
        if record["status"] != "pending_approval":
            return {
                "error": "not_pending",
                "execution_id": execution_id,
                "status": record["status"],
            }

        option = self.get_option(record["option_id"]) or {}
        if decision == "approve":
            record["status"] = "executed"
            record["approved_by"] = approved_by
            record["approval_reason"] = reason
            record["steps"] = self._simulate_steps(option) if option else record["steps"]
            record["world_model_effect"] = (
                self._apply_to_world_model(option, execution_id) if option else None
            )
            record["completed_at"] = utcnow().isoformat()
            outcome = "approved_and_simulated"
        else:
            record["status"] = "rejected"
            record["approved_by"] = approved_by
            record["rejection_reason"] = reason
            record["steps"] = [
                {**step, "status": "cancelled"} for step in record.get("steps", [])
            ]
            outcome = "rejected_by_human"

        audit_entry = audit.record(
            actor=approved_by,
            actor_type="human",
            action="approval_decision",
            target=record["target"],
            decision=f"{decision} execution {execution_id} ({record['action']})",
            confidence=option.get("score", 0.0),
            evidence=option.get("evidence", []),
            reasoning=reason or "no reason supplied",
            alternatives_considered=option.get("alternatives_considered", []),
            approved_by=approved_by,
            rollback_available=record["reversible"],
            outcome=outcome,
        )
        record["approval_audit_id"] = audit_entry["id"]
        return record

    def rollback(self, execution_id: str, actor: str = "decision_engine") -> Dict[str, Any]:
        record = self._executions.get(execution_id)
        if record is None:
            return {"error": "execution_not_found", "execution_id": execution_id}
        if record["status"] != "executed":
            return {
                "error": "not_rollbackable",
                "execution_id": execution_id,
                "status": record["status"],
            }

        restore_point = self._restore_points.pop(execution_id, None)
        restored = False
        if restore_point is not None:
            model = self.model
            model.entities = restore_point.entities
            model.relations = restore_point.relations
            model.adjacency = restore_point.adjacency
            model.observation_log = restore_point.observation_log
            model.detections = restore_point.detections
            model.revision = restore_point.revision + 1
            restored = True

        record["status"] = "rolled_back"
        record["rolled_back_at"] = utcnow().isoformat()
        record["steps"] = [
            {
                **step,
                "status": "rolled_back" if step.get("rollback_command") else "no_rollback_needed",
                "executed_rollback_command": step.get("rollback_command"),
                "mode": "simulated",
                "integration": "none",
            }
            for step in reversed(record.get("steps", []))
        ]
        record["world_model_restored"] = restored

        audit_entry = audit.record(
            actor=actor,
            actor_type="human" if actor != "decision_engine" else "ai_agent",
            action="rollback_response",
            target=record["target"],
            decision=f"roll back execution {execution_id} ({record['action']})",
            confidence=1.0 if restored else 0.0,
            reasoning=(
                "World model restored to the pre-execution snapshot; simulated rollback commands "
                "were replayed in reverse order. No external system was contacted."
            ),
            rollback_available=False,
            outcome="rolled_back" if restored else "rolled_back_without_restore_point",
        )
        record["rollback_audit_id"] = audit_entry["id"]
        return record

    def executions(self) -> List[Dict[str, Any]]:
        return list(self._executions.values())

    def get_execution(self, execution_id: str) -> Optional[Dict[str, Any]]:
        return self._executions.get(execution_id)


decision_engine = DecisionEngine()
