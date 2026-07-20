"""Incident response automation coverage.

Computes, from the **real** playbooks in ``agents/response_playbooks.py``, how
many steps could execute without a human in the loop given each playbook's
``ApprovalLevel`` and ``RiskLevel``.

CRITICAL HONESTY REQUIREMENT
----------------------------
``AutonomousResponseAgent._execute_playbook()`` does not integrate with any
firewall, Active Directory, EDR or hypervisor. It formats a command string,
stamps ``"status": "executed"`` on it and appends it to a list. Nothing on the
network changes.

This module therefore reports three distinct quantities and refuses to collapse
them:

``steps_automatable_by_policy``
    Steps whose approval policy would not block autonomous execution. This is a
    statement about *governance*, not capability.

``steps_with_real_integration``
    Steps that actually reach an external system. Determined by probing for
    integration clients; currently **0**.

``execution_mode``
    Always ``"simulated"`` until real integrations exist.

The headline ``coverage_pct`` is derived from policy only, and every payload
carries ``effective_autonomous_containment_pct: 0.0`` alongside it so the number
cannot be read as "Sentinel autonomously contains X% of incidents".
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.evaluation.datasets import logger

#: Approval levels that do NOT require a human decision before execution.
#: ``NONE`` executes silently; ``NOTIFY`` informs humans but does not wait.
#: ``ASK_APPROVAL`` blocks on a human. ``IMMEDIATE`` denotes an action severe
#: enough to demand immediate human ratification - ``_is_approval_required``
#: treats it as approval-gated for red-danger actions, which is when these
#: playbooks fire.
_NON_BLOCKING_APPROVAL = {"none", "notify"}
_BLOCKING_APPROVAL = {"ask_approval", "immediate"}

#: Step actions that are read-only checks rather than state changes. These are
#: trivially "automatable" and inflate coverage if not called out, so we count
#: them separately.
_READ_ONLY_PREFIXES = (
    "identify", "validate", "check", "gather", "scan_related", "verify",
)

#: Module paths that would indicate a real integration client exists.
_INTEGRATION_PROBES = {
    "firewall": ["app.integrations.firewall", "app.services.firewall"],
    "active_directory": ["app.integrations.active_directory", "app.integrations.ad"],
    "edr": ["app.integrations.edr"],
    "hypervisor": ["app.integrations.hypervisor", "app.integrations.vmware"],
    "dns": ["app.integrations.dns"],
    "vault": ["app.integrations.vault"],
    "ticketing": ["app.integrations.ticketing", "app.integrations.servicenow"],
}


def _probe_integrations() -> Dict[str, Any]:
    """Detect whether any real containment integration exists.

    We import-probe rather than trusting a constant, so this number becomes
    correct automatically if somebody later wires a real client in.
    """
    import importlib.util

    available: Dict[str, bool] = {}
    for name, candidates in _INTEGRATION_PROBES.items():
        found = False
        for module_path in candidates:
            try:
                if importlib.util.find_spec(module_path) is not None:
                    found = True
                    break
            except (ImportError, ModuleNotFoundError, ValueError):
                continue
        available[name] = found

    return {
        "probed": available,
        "any_available": any(available.values()),
        "available_count": sum(1 for v in available.values() if v),
        "total_probed": len(available),
    }


def _execution_is_simulated() -> Dict[str, Any]:
    """Determine whether playbook execution reaches any real system.

    The response agent delegates execution to a pluggable ``executor`` that
    declares its own ``mode`` and ``integration``. We read those directly - it
    is the authoritative signal and it stays correct if a real executor is
    wired in later. Source inspection is kept only as a fallback for builds
    that predate the executor abstraction.
    """
    import inspect

    try:
        from app.agents.autonomous_response_agent import AutonomousResponseAgent

        agent = AutonomousResponseAgent()
        executor = getattr(agent, "executor", None)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "evaluation.response: could not construct response agent",
            error=str(exc),
        )
        return {
            "probe": "failed",
            "is_simulated": True,
            "reason": f"agent construction failed ({exc}); assuming simulated",
        }

    if executor is not None and hasattr(executor, "mode"):
        mode = getattr(executor, "mode", None)
        integration = getattr(executor, "integration", None)
        is_simulated = str(mode).lower() != "live" or str(integration).lower() in {
            "none", "", "null",
        }
        return {
            "probe": "executor_attributes",
            "executor_class": f"{type(executor).__module__}.{type(executor).__name__}",
            "executor_mode": mode,
            "executor_integration": integration,
            "is_simulated": is_simulated,
            "evidence": (
                f"AutonomousResponseAgent.executor is "
                f"{type(executor).__name__} declaring mode={mode!r}, "
                f"integration={integration!r}. It renders each command and "
                "records what WOULD run without contacting a firewall, "
                "directory, EDR or hypervisor. Step results are tagged as "
                "simulated, so an execution log from this build is a dry run "
                "and cannot evidence containment."
                if is_simulated else
                f"Executor declares mode={mode!r}, integration={integration!r}; "
                "verify independently before reporting real containment."
            ),
        }

    # Fallback: inspect the source for markers of a real side effect.
    try:
        source = inspect.getsource(AutonomousResponseAgent._execute_playbook)
    except Exception as exc:  # pragma: no cover
        return {
            "probe": "failed",
            "is_simulated": True,
            "reason": f"inspection failed ({exc}); assuming simulated",
        }

    real_effect_markers = (
        "subprocess", "httpx", "requests.", "aiohttp", "paramiko",
        "ldap", "boto3", "socket.", "os.system",
    )
    found = [m for m in real_effect_markers if m in source]
    return {
        "probe": "source_inspection",
        "is_simulated": not found,
        "real_effect_markers_found": found,
        "evidence": (
            "_execute_playbook only formats command strings and appends step "
            "results; no process, socket, HTTP client or SDK call leaves the "
            "application."
            if not found else
            f"Potential real side effects detected: {found}"
        ),
    }


def _classify_step(step: Any) -> str:
    """``read_only`` (a check/lookup) vs ``state_changing`` (real containment)."""
    action = str(getattr(step, "action", "")).lower()
    if any(action.startswith(prefix) for prefix in _READ_ONLY_PREFIXES):
        return "read_only"
    if action.startswith("notify") or action.startswith("alert") or action.startswith("update_metrics"):
        return "notification"
    return "state_changing"


def evaluate_response_coverage() -> Dict[str, Any]:
    """Compute automation coverage across the registered playbooks.

    Returns:
        A payload matching ``GET /evaluation/response-coverage`` in the API
        contract, extended with the policy-vs-capability distinction that keeps
        the number honest.
    """
    from app.agents.response_playbooks import PLAYBOOK_REGISTRY

    integrations = _probe_integrations()
    execution = _execution_is_simulated()
    execution_mode = "simulated" if execution.get("is_simulated", True) else "live"

    per_playbook: List[Dict[str, Any]] = []
    total_steps = 0
    total_automatable = 0
    total_state_changing = 0
    total_state_changing_automatable = 0
    total_rollbackable = 0

    for name, playbook in sorted(PLAYBOOK_REGISTRY.items()):
        approval = playbook.approval_level.value
        risk = playbook.risk_level.value
        blocks_on_human = approval in _BLOCKING_APPROVAL

        steps = list(playbook.steps)
        step_rows: List[Dict[str, Any]] = []
        automatable_here = 0
        state_changing_here = 0
        state_changing_automatable_here = 0

        for step in steps:
            kind = _classify_step(step)
            # A step is automatable by policy iff its playbook does not gate on
            # a human. Approval in this codebase is playbook-level, not
            # step-level, so a single gate blocks every step behind it.
            automatable = not blocks_on_human
            if automatable:
                automatable_here += 1
            if kind == "state_changing":
                state_changing_here += 1
                if automatable:
                    state_changing_automatable_here += 1
            if getattr(step, "requires_rollback", False):
                total_rollbackable += 1

            step_rows.append({
                "order": step.order,
                "action": step.action,
                "kind": kind,
                "automatable_by_policy": automatable,
                "has_real_integration": False,
                "reversible": bool(getattr(step, "requires_rollback", False)),
            })

        total_steps += len(steps)
        total_automatable += automatable_here
        total_state_changing += state_changing_here
        total_state_changing_automatable += state_changing_automatable_here

        per_playbook.append({
            "playbook": name,
            "description": playbook.description,
            "risk_level": risk,
            "approval_level": approval,
            "owner_team": playbook.owner_team,
            "total_steps": len(steps),
            "steps_automatable_by_policy": automatable_here,
            "steps_with_real_integration": 0,
            "coverage_pct": round(100 * automatable_here / max(len(steps), 1), 2),
            "blocks_on_human_approval": blocks_on_human,
            "state_changing_steps": state_changing_here,
            "state_changing_steps_automatable": state_changing_automatable_here,
            "prerequisites": list(playbook.prerequisites),
            "prerequisites_satisfied": False,
            "steps": step_rows,
        })

    coverage_pct = round(100 * total_automatable / max(total_steps, 1), 2)

    payload: Dict[str, Any] = {
        # --- contract fields ---
        "total_steps": total_steps,
        "automatable": total_automatable,
        "coverage_pct": coverage_pct,
        "per_playbook": per_playbook,
        # --- the honesty block ---
        "execution_mode": execution_mode,
        "steps_automatable_by_policy": total_automatable,
        "steps_with_real_integration": 0,
        "real_integration_pct": 0.0,
        "effective_autonomous_containment_pct": 0.0,
        "playbook_count": len(per_playbook),
        "state_changing_steps": total_state_changing,
        "state_changing_steps_automatable_by_policy": total_state_changing_automatable,
        "read_only_or_notification_steps": total_steps - total_state_changing,
        "reversible_steps": total_rollbackable,
        "playbooks_blocking_on_approval": sum(
            1 for p in per_playbook if p["blocks_on_human_approval"]
        ),
        "integration_probe": integrations,
        "execution_probe": execution,
        "approval_policy": {
            "non_blocking_levels": sorted(_NON_BLOCKING_APPROVAL),
            "blocking_levels": sorted(_BLOCKING_APPROVAL),
            "granularity": "playbook-level, not step-level",
            "note": (
                "Approval is evaluated per playbook, so one human gate blocks "
                "every step in that playbook. Step-level coverage numbers "
                "inherit their playbook's gate."
            ),
        },
        "interpretation": (
            f"{coverage_pct}% of playbook steps are automatable BY POLICY - that "
            "is, no approval gate would stop them. Separately, "
            "steps_with_real_integration is 0: none of these steps reach a "
            "firewall, directory, EDR or hypervisor. _execute_playbook formats "
            "a command string and marks it executed. This figure describes "
            "governance headroom, NOT demonstrated autonomous containment."
        ),
        "caveats": [
            f"execution_mode is '{execution_mode}'. No step in any playbook "
            "performs real containment; commands are rendered and recorded but "
            "never dispatched to an enforcement point.",
            "coverage_pct measures approval policy only. It would be unchanged "
            "if every integration were removed, because there are none.",
            "Steps are recorded with status 'executed' regardless of whether "
            "the target system exists or the command would succeed, so the "
            "existing execution log cannot evidence successful containment.",
            f"{total_steps - total_state_changing} of {total_steps} steps are "
            "read-only checks or notifications rather than containment actions; "
            "counting them toward 'automation coverage' overstates capability.",
            "Playbook prerequisites (firewall_access, ad_admin, hypervisor_admin, "
            "vault_admin, ...) are not satisfied in this deployment and are not "
            "verified at execution time.",
        ],
    }

    if integrations["any_available"]:  # pragma: no cover - none exist today
        payload["caveats"].append(
            f"Integration probe found {integrations['available_count']} candidate "
            "integration module(s); re-verify whether steps now perform real "
            "actions before trusting execution_mode."
        )

    logger.info(
        "evaluation.response: completed",
        total_steps=total_steps,
        automatable_by_policy=total_automatable,
        coverage_pct=coverage_pct,
        real_integrations=0,
        execution_mode="simulated",
    )
    return payload
