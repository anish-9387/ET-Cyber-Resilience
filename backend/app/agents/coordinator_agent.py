from typing import Dict, Any, Optional, List, Callable, Awaitable
from datetime import datetime
from collections import defaultdict
from app.agents.base_agent import BaseAgent
from app.agents.behaviour_agent import BehaviourLearningAgent
from app.agents.attack_story_builder import AttackStoryBuilder
from app.agents.threat_prediction_agent import ThreatPredictionAgent
from app.agents.digital_twin_agent import DigitalTwinAgent
from app.agents.blast_radius_agent import BlastRadiusAgent
from app.agents.autonomous_response_agent import AutonomousResponseAgent
from app.agents.adaptive_patch_agent import AdaptivePatchAgent
from app.agents.learning_agent import LearningAgent
from app.agents.mitre_mapper import mitre_mapper
from app.agents.threat_correlation_agent import ThreatCorrelationAgent
from app.agents.vulnerability_prioritization import VulnerabilityPrioritizationAgent
from app.core.logger import logger
from app.core.event_bus import event_bus
import json, hashlib


class Workflow:
    def __init__(self, workflow_id: str, workflow_type: str, input_data: Dict[str, Any]):
        self.workflow_id = workflow_id
        self.workflow_type = workflow_type
        self.input_data = input_data
        self.steps: List[Dict] = []
        self.results: Dict[str, Any] = {}
        self.status = "pending"
        self.created_at = datetime.utcnow()
        self.completed_at: Optional[datetime] = None
        self.error: Optional[str] = None

    def add_step(self, agent_name: str, action: str):
        self.steps.append({"agent": agent_name, "action": action, "status": "pending"})

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "workflow_type": self.workflow_type,
            "steps": self.steps,
            "results": {k: v for k, v in self.results.items() if k != "raw_data"},
            "status": self.status,
            "created_at": self.created_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error": self.error,
        }


class CoordinatorAgent(BaseAgent):
    def __init__(self, version: str = "1.0.0"):
        super().__init__(
            name="coordinator_agent",
            agent_type="coordinator",
            version=version,
        )
        self.behaviour_agent = BehaviourLearningAgent()
        self.attack_story_builder = AttackStoryBuilder()
        self.threat_prediction = ThreatPredictionAgent()
        self.digital_twin = DigitalTwinAgent()
        self.blast_radius = BlastRadiusAgent()
        self.response_agent = AutonomousResponseAgent()
        self.patch_agent = AdaptivePatchAgent()
        self.learning_agent = LearningAgent()
        self.threat_correlator = ThreatCorrelationAgent()
        self.vuln_prioritization = VulnerabilityPrioritizationAgent()

        self.agent_registry: Dict[str, BaseAgent] = {
            "behaviour": self.behaviour_agent,
            "attack_story": self.attack_story_builder,
            "threat_prediction": self.threat_prediction,
            "digital_twin": self.digital_twin,
            "blast_radius": self.blast_radius,
            "response": self.response_agent,
            "patch": self.patch_agent,
            "learning": self.learning_agent,
            "threat_correlation": self.threat_correlator,
            "vulnerability": self.vuln_prioritization,
        }

        self.workflows: Dict[str, Workflow] = {}
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        self._register_default_handlers()

    def _register_default_handlers(self):
        self.event_handlers["alert.raw"].append(self._handle_raw_alert)
        self.event_handlers["threat.critical"].append(self._handle_critical_threat)
        self.event_handlers["behaviour.anomaly"].append(self._handle_behaviour_anomaly)

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        self.last_run = datetime.utcnow()
        action = input_data.get("action", "route")

        try:
            if action == "route":
                return await self._route_event(input_data)
            elif action == "ingest_alert":
                return await self._ingest_alert(input_data)
            elif action == "run_workflow":
                return await self._run_workflow(input_data)
            elif action == "get_workflow":
                return self._get_workflow(input_data)
            elif action == "get_agent_status":
                return self._get_all_agent_status()
            elif action == "get_agent":
                return self._get_agent_info(input_data)
            elif action == "handle_event":
                return await self._handle_event(input_data)
            elif action == "register_handler":
                return self._register_handler(input_data)
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        except Exception as e:
            logger.error(f"CoordinatorAgent error", error=str(e))
            self.update_metrics(False)
            return {"success": False, "error": str(e)}

    async def _route_event(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        event = input_data.get("event", input_data)
        event_type = event.get("event_type", event.get("type", "unknown"))
        source = event.get("source", event.get("entity_id"))

        mapped = mitre_mapper.map_event(event)
        event["mitre_mapping"] = mapped

        routing_plan = self._determine_routing(event_type, mapped, source)

        results = {}
        for target_agent, action in routing_plan:
            agent = self.agent_registry.get(target_agent)
            if agent:
                try:
                    agent_result = await agent.process({
                        "action": action,
                        **event,
                    })
                    results[target_agent] = agent_result
                except Exception as e:
                    logger.error(f"Agent {target_agent} failed", error=str(e))
                    results[target_agent] = {"success": False, "error": str(e)}

        routing = [{"agent": a, "action": ac} for a, ac in routing_plan]

        result = {
            "success": True,
            "event_id": event.get("event_id", event.get("alert_id", "unknown")),
            "event_type": event_type,
            "routing_plan": routing,
            "results": results,
            "mitre_mapping": mapped,
        }

        await self.publish_event("coordinator.routed", {
            "event_type": event_type,
            "agents_involved": [a for a, _ in routing_plan],
        })

        self.update_metrics(True)
        return result

    async def _ingest_alert(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        alert = input_data.get("alert", input_data)
        if "alert_id" not in alert:
            alert["alert_id"] = hashlib.md5(json.dumps(alert, default=str).encode()).hexdigest()[:12]

        mapped = mitre_mapper.map_event(alert)
        alert["mitre_mapping"] = mapped

        correlate_result = await self.threat_correlator.process({
            "action": "ingest_event",
            "event": alert,
        })

        if mapped["mapped"]:
            story_result = await self.attack_story_builder.process({
                "action": "ingest_alert",
                "alert": alert,
            })

            if story_result.get("story", {}).get("confidence", 0) > 0.7:
                predict_result = await self.threat_prediction.process({
                    "observations": [alert],
                    "use_llm": False,
                })

                if predict_result.get("predictions"):
                    top_threat = predict_result["predictions"][0]
                    if top_threat.get("probability", 0) > 0.6:
                        await self.response_agent.process({
                            "action": "execute",
                            "action_type": self._recommend_preventive_action(top_threat),
                            "target": top_threat.get("targets", ["unknown"])[0] if top_threat.get("targets") else "unknown",
                            "threat_info": top_threat,
                        })

        return {
            "success": True,
            "alert_id": alert["alert_id"],
            "mitre_mapping": mapped,
            "correlation": correlate_result,
        }

    async def _run_workflow(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        workflow_type = input_data.get("workflow_type", "general")
        workflow_id = input_data.get("workflow_id") or hashlib.md5(
            f"{workflow_type}:{datetime.utcnow().isoformat()}".encode()
        ).hexdigest()[:16]

        workflow = Workflow(workflow_id, workflow_type, input_data)
        self.workflows[workflow_id] = workflow

        workflow_def = self._get_workflow_definition(workflow_type)
        if not workflow_def:
            return {"success": False, "error": f"Unknown workflow type: {workflow_type}"}

        for step in workflow_def:
            workflow.add_step(step["agent"], step["action"])

        workflow.status = "running"

        for step in workflow.steps:
            agent = self.agent_registry.get(step["agent"])
            if not agent:
                step["status"] = "failed"
                workflow.error = f"Agent {step['agent']} not found"
                continue

            try:
                step["status"] = "running"
                result = await agent.process({
                    "action": step["action"],
                    **input_data.get("params", {}),
                    "workflow_id": workflow_id,
                })

                workflow.results[step["agent"]] = result
                step["status"] = "completed" if result.get("success") else "failed"
                step["result"] = result
            except Exception as e:
                step["status"] = "failed"
                step["error"] = str(e)
                workflow.error = f"Step {step['agent']} failed: {e}"

        workflow.status = "completed" if not workflow.error else "failed"
        workflow.completed_at = datetime.utcnow()

        return {"success": True, "workflow": workflow.to_dict()}

    def _get_workflow(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        workflow_id = input_data.get("workflow_id")
        if workflow_id and workflow_id in self.workflows:
            return {"success": True, "workflow": self.workflows[workflow_id].to_dict()}
        return {"success": False, "error": "Workflow not found"}

    def _get_all_agent_status(self) -> Dict[str, Any]:
        statuses = {}
        for name, agent in self.agent_registry.items():
            statuses[name] = agent.get_status()
        return {"success": True, "agents": statuses}

    def _get_agent_info(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        agent_name = input_data.get("agent")
        if agent_name and agent_name in self.agent_registry:
            return {"success": True, "agent": self.agent_registry[agent_name].get_status()}
        return {"success": False, "error": "Agent not found"}

    async def _handle_event(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        topic = input_data.get("topic", input_data.get("event_type", "general"))
        data = input_data.get("data", input_data)

        handlers = self.event_handlers.get(topic, [])
        if not handlers:
            generic_handlers = self.event_handlers.get("general", [])
            handlers = generic_handlers

        results = []
        for handler in handlers:
            try:
                result = await handler(data)
                results.append({"handler": handler.__name__, "success": True, "result": result})
            except Exception as e:
                results.append({"handler": handler.__name__, "success": False, "error": str(e)})

        return {"success": True, "topic": topic, "handlers_executed": len(handlers), "results": results}

    def _register_handler(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        topic = input_data.get("topic")
        handler_name = input_data.get("handler")
        if topic and handler_name:
            logger.info(f"Handler registration requested but not supported dynamically: {handler_name}")
            return {"success": False, "error": "Dynamic handler registration not supported"}
        return {"success": False, "error": "topic and handler required"}

    async def _handle_raw_alert(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return await self._ingest_alert({"alert": data})

    async def _handle_critical_threat(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return await self._run_workflow({
            "workflow_type": "critical_incident",
            "params": data,
        })

    async def _handle_behaviour_anomaly(self, data: Dict[str, Any]) -> Dict[str, Any]:
        return await self._route_event({"event": data, "event_type": "behaviour_anomaly"})

    def _determine_routing(self, event_type: str, mitre_mapping: Dict, source: Any) -> List[tuple]:
        routing = []

        tactic = mitre_mapping.get("tactic", "").lower().replace(" ", "_")
        technique = mitre_mapping.get("technique_id", "")

        routing.append(("behaviour", "analyze"))

        routing.append(("threat_correlation", "ingest_event"))

        if tactic:
            routing.append(("attack_story", "build_story"))

        if tactic in {"credential_access", "lateral_movement", "impact", "exfiltration"}:
            routing.append(("threat_prediction", "predict"))

        if source:
            routing.append(("digital_twin", "query"))
            routing.append(("blast_radius", "calculate"))

        immediate_response_techniques = {"T1486", "T1490", "T1485", "T1021", "T1550"}
        if technique in immediate_response_techniques:
            routing.append(("response", "execute"))

        if technique and mitre_mapping.get("confidence", 0) > 0.5:
            routing.append(("learning", "recall"))

        return routing

    def _get_workflow_definition(self, workflow_type: str) -> Optional[List[Dict]]:
        workflows = {
            "critical_incident": [
                {"agent": "threat_correlation", "action": "correlate"},
                {"agent": "attack_story", "action": "build_story"},
                {"agent": "threat_prediction", "action": "predict"},
                {"agent": "digital_twin", "action": "query"},
                {"agent": "blast_radius", "action": "calculate"},
                {"agent": "response", "action": "execute"},
                {"agent": "learning", "action": "store"},
            ],
            "incident_investigation": [
                {"agent": "behaviour", "action": "analyze"},
                {"agent": "threat_correlation", "action": "correlate"},
                {"agent": "attack_story", "action": "build_story"},
                {"agent": "threat_prediction", "action": "predict"},
                {"agent": "digital_twin", "action": "query"},
                {"agent": "blast_radius", "action": "calculate"},
            ],
            "vulnerability_assessment": [
                {"agent": "vulnerability", "action": "prioritize"},
                {"agent": "patch", "action": "prioritize"},
                {"agent": "digital_twin", "action": "query"},
                {"agent": "blast_radius", "action": "calculate"},
            ],
            "behaviour_investigation": [
                {"agent": "behaviour", "action": "analyze"},
                {"agent": "threat_correlation", "action": "correlate"},
                {"agent": "learning", "action": "recall"},
            ],
            "post_incident_review": [
                {"agent": "learning", "action": "store"},
                {"agent": "learning", "action": "extract_patterns"},
                {"agent": "patch", "action": "prioritize"},
                {"agent": "vulnerability", "action": "prioritize"},
            ],
        }
        return workflows.get(workflow_type)

    def _recommend_preventive_action(self, threat_prediction: Dict[str, Any]) -> str:
        tactic = threat_prediction.get("tactic", "").lower()
        technique = threat_prediction.get("technique_id", "")

        if "lateral_movement" in tactic or technique == "T1021":
            return "network_isolation"
        elif "impact" in tactic or technique == "T1486":
            return "snapshot_vm"
        elif "exfiltration" in tactic or technique == "T1048":
            return "block_ip"
        elif "credential_access" in tactic or technique == "T1003":
            return "rotate_credentials"
        elif "persistence" in tactic:
            return "kill_process"
        else:
            return "notify_soc"
