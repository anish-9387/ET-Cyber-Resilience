from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from enum import Enum
from app.agents.base_agent import BaseAgent
from app.agents.response_playbooks import (
    Playbook, RiskLevel, ApprovalLevel, get_playbook, PLAYBOOK_REGISTRY,
    block_ip_playbook, disable_account_playbook, kill_process_playbook,
    snapshot_vm_playbook, quarantine_host_playbook, rotate_credentials_playbook,
    network_isolation_playbook, notify_soc_playbook
)
from app.core.logger import logger
from app.core.config import settings
import json, hashlib


class ExecutionStatus(Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


class ResponseAction:
    def __init__(self, action_type: str, target: str, playbook: str, params: Dict[str, Any]):
        self.action_id = hashlib.md5(f"{action_type}:{target}:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:12]
        self.action_type = action_type
        self.target = target
        self.playbook_name = playbook
        self.params = params
        self.status = ExecutionStatus.PENDING
        self.approval_required = False
        self.approved_by: Optional[str] = None
        self.steps_executed: List[Dict] = []
        self.started_at: Optional[datetime] = None
        self.completed_at: Optional[datetime] = None
        self.error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target": self.target,
            "playbook": self.playbook_name,
            "params": self.params,
            "status": self.status.value,
            "approval_required": self.approval_required,
            "approved_by": self.approved_by,
            "steps_executed": self.steps_executed,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
        }


class AutonomousResponseAgent(BaseAgent):
    def __init__(self, version: str = "1.0.0"):
        super().__init__(
            name="autonomous_response_agent",
            agent_type="autonomous_response",
            version=version,
        )
        self.active_actions: Dict[str, ResponseAction] = {}
        self.action_history: List[Dict[str, Any]] = []
        self.ot_critical_assets: List[str] = []
        self.approval_timeout_minutes: int = 5

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        self.last_run = datetime.utcnow()
        action = input_data.get("action", "execute")

        try:
            if action == "execute":
                return await self._execute_action(input_data)
            elif action == "approve":
                return await self._approve_action(input_data)
            elif action == "reject":
                return await self._reject_action(input_data)
            elif action == "get_status":
                return self._get_status(input_data)
            elif action == "get_active_actions":
                return self._get_active_actions()
            elif action == "rollback":
                return await self._rollback_action(input_data)
            elif action == "set_ot_assets":
                return self._set_ot_assets(input_data)
            elif action == "classify_danger":
                return self._classify_danger(input_data)
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        except Exception as e:
            logger.error(f"AutonomousResponseAgent error", error=str(e))
            self.update_metrics(False)
            return {"success": False, "error": str(e)}

    async def _execute_action(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        action_type = input_data.get("action_type", "")
        target = input_data.get("target", "")
        params = input_data.get("params", {})
        threat_info = input_data.get("threat_info", {})

        if not action_type or not target:
            return {"success": False, "error": "action_type and target required"}

        playbook = get_playbook(action_type)
        if not playbook:
            return {"success": False, "error": f"No playbook found for action type: {action_type}"}

        danger_level = self._classify_danger_level(action_type, target, threat_info)

        response = ResponseAction(action_type, target, playbook.name, params)
        response.approval_required = self._is_approval_required(playbook, danger_level, target)

        if self._is_ot_critical(target) and danger_level in {"red", "orange"}:
            response.approval_required = True
            response.status = ExecutionStatus.PENDING

        if not response.approval_required:
            response.status = ExecutionStatus.RUNNING
            response.started_at = datetime.utcnow()
            result = await self._execute_playbook(response, playbook)
            response.completed_at = datetime.utcnow()

            if result["success"]:
                response.status = ExecutionStatus.COMPLETED
                self.update_metrics(True)
            else:
                response.status = ExecutionStatus.FAILED
                response.error = result.get("error")
                self.update_metrics(False)

            await self.publish_event("response.executed", {
                "action_id": response.action_id,
                "action_type": action_type,
                "target": target,
                "status": response.status.value,
                "danger_level": danger_level,
            })
        else:
            response.status = ExecutionStatus.PENDING
            await self.publish_event("response.approval_needed", {
                "action_id": response.action_id,
                "action_type": action_type,
                "target": target,
                "danger_level": danger_level,
                "playbook": playbook.name,
                "approval_timeout_minutes": self.approval_timeout_minutes,
            })

        self.active_actions[response.action_id] = response
        self.action_history.append(response.to_dict())

        return {
            "success": True,
            "action_id": response.action_id,
            "status": response.status.value,
            "approval_required": response.approval_required,
            "approval_timeout_minutes": self.approval_timeout_minutes if response.approval_required else None,
            "danger_level": danger_level,
        }

    async def _approve_action(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        action_id = input_data.get("action_id")
        approved_by = input_data.get("approved_by", "soc_analyst")

        if not action_id or action_id not in self.active_actions:
            return {"success": False, "error": "Action not found"}

        response = self.active_actions[action_id]
        if response.status != ExecutionStatus.PENDING:
            return {"success": False, "error": f"Action is in {response.status.value} state, not pending"}

        response.approved_by = approved_by
        response.status = ExecutionStatus.RUNNING
        response.started_at = datetime.utcnow()

        playbook = get_playbook(response.playbook_name)
        if not playbook:
            return {"success": False, "error": "Playbook not found"}

        result = await self._execute_playbook(response, playbook)
        response.completed_at = datetime.utcnow()

        if result["success"]:
            response.status = ExecutionStatus.COMPLETED
            self.update_metrics(True)
        else:
            response.status = ExecutionStatus.FAILED
            response.error = result.get("error")
            self.update_metrics(False)

        await self.publish_event("response.approved", {
            "action_id": action_id,
            "approved_by": approved_by,
            "status": response.status.value,
        })

        return {"success": True, "action": response.to_dict()}

    async def _reject_action(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        action_id = input_data.get("action_id")
        reason = input_data.get("reason", "Rejected by analyst")

        if not action_id or action_id not in self.active_actions:
            return {"success": False, "error": "Action not found"}

        response = self.active_actions[action_id]
        response.status = ExecutionStatus.REJECTED
        response.error = reason

        await self.publish_event("response.rejected", {
            "action_id": action_id,
            "reason": reason,
        })

        return {"success": True, "action": response.to_dict()}

    async def _execute_playbook(self, response: ResponseAction, playbook: Playbook) -> Dict[str, Any]:
        try:
            for step in playbook.steps:
                command = step.command.format(**response.params, **{
                    "ip": response.params.get("ip", response.target),
                    "user": response.params.get("user", response.target),
                    "hostname": response.params.get("hostname", response.target),
                    "pid": response.params.get("pid", response.target),
                    "vm_id": response.params.get("vm_id", response.target),
                    "host_id": response.params.get("host_id", response.target),
                    "credential_id": response.params.get("credential_id", response.target),
                    "segment_id": response.params.get("segment_id", response.target),
                    "alert_id": response.params.get("alert_id", response.target),
                    "timestamp": datetime.utcnow().strftime("%Y%m%d%H%M%S"),
                })

                step_result = {
                    "step": step.order,
                    "action": step.action,
                    "command": command,
                    "status": "executed",
                    "timestamp": datetime.utcnow().isoformat(),
                }
                response.steps_executed.append(step_result)

                if step.requires_rollback:
                    response.params[f"_rollback_{step.action}"] = step.rollback_command

            return {"success": True, "steps": len(playbook.steps)}

        except Exception as e:
            logger.error(f"Playbook execution failed", playbook=playbook.name, error=str(e))
            return {"success": False, "error": str(e)}

    async def _rollback_action(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        action_id = input_data.get("action_id")
        if not action_id or action_id not in self.active_actions:
            return {"success": False, "error": "Action not found"}

        response = self.active_actions[action_id]
        rollback_results = []

        for step in reversed(response.steps_executed):
            rollback_cmd = response.params.get(f"_rollback_{step['action']}")
            if rollback_cmd:
                rollback_results.append({
                    "step": step["step"],
                    "rollback_command": rollback_cmd,
                    "status": "executed",
                })

        response.status = ExecutionStatus.ROLLED_BACK
        response.error = "Rolled back"

        await self.publish_event("response.rolled_back", {
            "action_id": action_id,
            "rollback_steps": len(rollback_results),
        })

        return {"success": True, "rollback_results": rollback_results}

    def _classify_danger_level(self, action_type: str, target: str, threat_info: Dict[str, Any]) -> str:
        technique = threat_info.get("technique_id", threat_info.get("technique", ""))
        severity = threat_info.get("severity", threat_info.get("risk_score", 5))
        if isinstance(severity, str):
            try:
                severity = int(severity)
            except ValueError:
                severity = 5

        if technique in {"T1486", "T1490", "T1485"} or severity >= 9:
            return "red"
        elif technique in {"T1021", "T1003", "T1550", "T1048"} or severity >= 7:
            return "orange"
        elif technique in {"T1059", "T1562", "T1547"} or severity >= 5:
            return "yellow"
        else:
            return "green"

    def _is_approval_required(self, playbook: Playbook, danger_level: str, target: str) -> bool:
        if not settings.HUMAN_APPROVAL_REQUIRED:
            return False

        if danger_level == "red":
            if self._is_ot_critical(target):
                return True
            return playbook.approval_level.value in {"ask_approval", "immediate"}

        if danger_level == "orange":
            return playbook.approval_level.value == "ask_approval"

        if danger_level == "yellow":
            return False

        return False

    def _is_ot_critical(self, target: str) -> bool:
        return target in self.ot_critical_assets

    def _set_ot_assets(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        assets = input_data.get("assets", [])
        if isinstance(assets, list):
            self.ot_critical_assets = assets
            return {"success": True, "ot_assets_count": len(assets)}
        return {"success": False, "error": "assets must be a list"}

    def _classify_danger(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        action_type = input_data.get("action_type", "")
        target = input_data.get("target", "")
        threat_info = input_data.get("threat_info", {})
        danger = self._classify_danger_level(action_type, target, threat_info)
        return {"success": True, "danger_level": danger}

    def _get_status(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        action_id = input_data.get("action_id")
        if action_id and action_id in self.active_actions:
            return {"success": True, "action": self.active_actions[action_id].to_dict()}
        return {"success": False, "error": "Action not found"}

    def _get_active_actions(self) -> Dict[str, Any]:
        active = {aid: a.to_dict() for aid, a in self.active_actions.items()
                  if a.status in {ExecutionStatus.PENDING, ExecutionStatus.RUNNING, ExecutionStatus.APPROVED}}
        return {
            "success": True,
            "count": len(active),
            "actions": list(active.values()),
        }
