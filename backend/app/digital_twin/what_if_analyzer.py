from typing import Dict, Any, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass, field
import uuid
from datetime import datetime, timezone
from app.core.logger import logger
from app.digital_twin.state_manager import (
    state_manager,
    EntityState,
    EntityCategory,
    EntityStatus,
)
from app.digital_twin.twin_manager import twin_manager
from app.digital_twin.simulation_engine import (
    simulation_engine,
    SimulationScenario,
    SimulationStep,
    SimulationStepType,
    SimulationReport,
)
from app.knowledge_graph.graph_manager import graph_manager


class WhatIfScenarioType(str, Enum):
    PATCH_SERVER = "patch_server"
    ISOLATE_VLAN = "isolate_vlan"
    ADD_FIREWALL_RULE = "add_firewall_rule"
    REMOVE_ACCESS = "remove_access"
    ENABLE_MFA = "enable_mfa"
    NETWORK_SEGMENT = "network_segment"
    DISABLE_SERVICE = "disable_service"
    ADD_MONITORING = "add_monitoring"
    UPGRADE_FIRMWARE = "upgrade_firmware"
    CUSTOM = "custom"


@dataclass
class WhatIfScenario:
    scenario_id: str
    name: str
    description: str
    scenario_type: WhatIfScenarioType
    target_entity_id: str
    target_entity_name: str
    action: str
    changes: Dict[str, Any] = field(default_factory=dict)
    baseline_scenario_id: Optional[str] = None


@dataclass
class WhatIfResult:
    result_id: str
    scenario: WhatIfScenario
    baseline_report: Optional[SimulationReport]
    mitigated_report: Optional[SimulationReport]
    risk_reduction: float
    impact_reduction: float
    blast_radius_reduction: int
    effectiveness_score: float
    analysis: Dict[str, Any] = field(default_factory=dict)
    recommendations: List[str] = field(default_factory=list)
    summary: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "result_id": self.result_id,
            "scenario_name": self.scenario.name,
            "scenario_type": self.scenario.scenario_type.value,
            "target": self.scenario.target_entity_name,
            "action": self.scenario.action,
            "risk_reduction": self.risk_reduction,
            "impact_reduction": self.impact_reduction,
            "blast_radius_reduction": self.blast_radius_reduction,
            "effectiveness_score": self.effectiveness_score,
            "analysis": self.analysis,
            "recommendations": self.recommendations,
            "summary": self.summary,
        }


SCENARIO_TEMPLATES = {
    WhatIfScenarioType.PATCH_SERVER: {
        "action": "Apply critical security patches",
        "changes_description": "Server patches applied, vulnerabilities remediated",
        "changes": {"patch_level": "latest", "vulnerabilities_resolved": True},
    },
    WhatIfScenarioType.ISOLATE_VLAN: {
        "action": "Isolate VLAN from rest of network",
        "changes_description": "Network segmentation applied, VLAN isolated",
        "changes": {"is_isolated": True, "network_access": "restricted"},
    },
    WhatIfScenarioType.ADD_FIREWALL_RULE: {
        "action": "Add firewall rule to block traffic",
        "changes_description": "New firewall rule deployed to restrict east-west traffic",
        "changes": {"rules_count": "+1", "block_enabled": True},
    },
    WhatIfScenarioType.REMOVE_ACCESS: {
        "action": "Revoke user access privileges",
        "changes_description": "User privileges reduced to least privilege",
        "changes": {"privilege_level": "restricted", "is_admin": False},
    },
    WhatIfScenarioType.ENABLE_MFA: {
        "action": "Enable multi-factor authentication",
        "changes_description": "MFA enforced for all user accounts",
        "changes": {"mfa_enabled": True, "mfa_type": "totp"},
    },
    WhatIfScenarioType.NETWORK_SEGMENT: {
        "action": "Implement network segmentation",
        "changes_description": "Medical devices and IT systems separated into isolated segments",
        "changes": {"segmentation": "enforced", "east_west_traffic": "blocked"},
    },
    WhatIfScenarioType.DISABLE_SERVICE: {
        "action": "Disable vulnerable service",
        "changes_description": "Non-critical vulnerable service disabled",
        "changes": {"service_status": "disabled", "port": "closed"},
    },
    WhatIfScenarioType.ADD_MONITORING: {
        "action": "Deploy additional monitoring",
        "changes_description": "Enhanced monitoring and detection controls added",
        "changes": {"monitoring_level": "enhanced", "detection_coverage": "comprehensive"},
    },
    WhatIfScenarioType.UPGRADE_FIRMWARE: {
        "action": "Upgrade device firmware",
        "changes_description": "Device firmware updated to latest patched version",
        "changes": {"firmware_version": "latest", "vulnerabilities_patched": True},
    },
}


class WhatIfAnalyzer:
    def __init__(self):
        self._results: Dict[str, WhatIfResult] = {}

    async def analyze(
        self,
        scenario_type: WhatIfScenarioType,
        target_entity_id: str,
        custom_changes: Dict[str, Any] = None,
        attack_scenario_id: str = None,
    ) -> WhatIfResult:
        logger.info(
            "Starting what-if analysis",
            scenario_type=scenario_type.value,
            target=target_entity_id,
        )

        template = SCENARIO_TEMPLATES.get(scenario_type, {})
        scenario = WhatIfScenario(
            scenario_id=str(uuid.uuid4()),
            name=f"What-If: {template.get('action', scenario_type.value)} on {target_entity_id[:16]}",
            description=template.get("changes_description", ""),
            scenario_type=scenario_type,
            target_entity_id=target_entity_id,
            target_entity_name=self._get_entity_name(target_entity_id),
            action=template.get("action", "Apply change"),
            changes=custom_changes or template.get("changes", {}),
        )

        attack_scenario = await self._get_or_create_attack_scenario(
            attack_scenario_id, target_entity_id
        )

        fork_id, _ = await twin_manager.fork_twin(
            name=f"whatif_baseline_{scenario.scenario_id}"
        )

        try:
            await twin_manager.restore_fork(fork_id)
            baseline_report = await simulation_engine.run_scenario(attack_scenario)
        finally:
            await twin_manager.discard_fork(fork_id)

        fork_id2, _ = await twin_manager.fork_twin(
            name=f"whatif_mitigated_{scenario.scenario_id}"
        )

        try:
            await twin_manager.restore_fork(fork_id2)
            await self._apply_mitigation(scenario)
            mitigated_report = await simulation_engine.run_scenario(attack_scenario)
        finally:
            await twin_manager.discard_fork(fork_id2)

        result = self._compute_result(scenario, baseline_report, mitigated_report)
        self._results[result.result_id] = result

        logger.info(
            "What-if analysis complete",
            result_id=result.result_id,
            effectiveness=result.effectiveness_score,
        )

        return result

    async def _get_entity_name(self, entity_id: str) -> str:
        entity = state_manager.get_entity(entity_id)
        if entity:
            return (
                entity.properties.get("hostname")
                or entity.properties.get("name")
                or entity.properties.get("username")
                or entity_id[:16]
            )
        return entity_id[:16]

    async def _get_or_create_attack_scenario(
        self, attack_scenario_id: Optional[str], target_entity_id: str
    ) -> SimulationScenario:
        if attack_scenario_id:
            scenario = simulation_engine.get_scenario(attack_scenario_id)
            if scenario:
                return scenario

        scenario = simulation_engine.get_scenario("scenario-ransomware-001")
        if scenario:
            scenario.starting_entity_id = target_entity_id
            scenario.starting_entity_name = self._get_entity_name_sync(target_entity_id)
            return scenario

        return SimulationScenario(
            scenario_id="whatif-default",
            name=f"Default attack on {target_entity_id}",
            description="Default attack scenario for what-if analysis",
            attack_type="generic",
            starting_entity_id=target_entity_id,
            starting_entity_name=self._get_entity_name_sync(target_entity_id),
            steps=[
                SimulationStep(
                    step_id="wi-step-1",
                    step_type=SimulationStepType.INITIAL_ACCESS,
                    name="Initial Compromise",
                    description="Attacker gains initial access",
                    target_entity_id=target_entity_id,
                    target_entity_name=self._get_entity_name_sync(target_entity_id),
                    success_probability=0.8,
                    detection_chance=0.2,
                    duration_seconds=60,
                    mitigations=["Patching", "Access control"],
                ),
                SimulationStep(
                    step_id="wi-step-2",
                    step_type=SimulationStepType.LATERAL_MOVEMENT,
                    name="Lateral Movement",
                    description="Move to adjacent systems",
                    target_entity_id=target_entity_id,
                    target_entity_name=self._get_entity_name_sync(target_entity_id),
                    success_probability=0.7,
                    detection_chance=0.3,
                    duration_seconds=120,
                    mitigations=["Network segmentation", "Firewall rules"],
                ),
                SimulationStep(
                    step_id="wi-step-3",
                    step_type=SimulationStepType.IMPACT,
                    name="Impact",
                    description="Cause disruption to systems",
                    target_entity_id=target_entity_id,
                    target_entity_name=self._get_entity_name_sync(target_entity_id),
                    success_probability=0.9,
                    detection_chance=0.5,
                    duration_seconds=300,
                    mitigations=["Backups", "Incident response"],
                ),
            ],
        )

    def _get_entity_name_sync(self, entity_id: str) -> str:
        entity = state_manager.get_entity(entity_id)
        if entity:
            return (
                entity.properties.get("hostname")
                or entity.properties.get("name")
                or entity.properties.get("username")
                or entity_id[:16]
            )
        return entity_id[:16]

    async def _apply_mitigation(self, scenario: WhatIfScenario):
        entity = state_manager.get_entity(scenario.target_entity_id)
        if not entity:
            logger.warning("Target entity not found for mitigation", target=scenario.target_entity_id)
            return

        await state_manager.update_properties(
            scenario.target_entity_id,
            scenario.changes,
            source="what_if_analysis",
            description=f"Applied: {scenario.action}",
        )

        if scenario.scenario_type == WhatIfScenarioType.PATCH_SERVER:
            connected_ids = list(entity.connected_entities)
            for cid in connected_ids:
                ce = state_manager.get_entity(cid)
                if ce and ce.category == EntityCategory.APPLICATION:
                    await state_manager.update_properties(
                        cid,
                        {"has_vulnerabilities": False},
                        source="what_if_analysis",
                        description="Dependency vulnerability resolved",
                    )

        if scenario.scenario_type == WhatIfScenarioType.ISOLATE_VLAN:
            connected_ids = list(entity.connected_entities)
            for cid in connected_ids:
                await state_manager.remove_connection(scenario.target_entity_id, cid)
            for cid in connected_ids:
                await state_manager.update_status(
                    cid,
                    EntityStatus.ISOLATED,
                    source="vlan_isolation",
                    description=f"Isolated due to VLAN segmentation ({scenario.target_entity_id})",
                    propagate=False,
                )

        if scenario.scenario_type == WhatIfScenarioType.ENABLE_MFA:
            if entity.category == EntityCategory.USER:
                connected_ids = list(entity.connected_entities)
                for cid in connected_ids:
                    ce = state_manager.get_entity(cid)
                    if ce and ce.category == EntityCategory.IDENTITY:
                        await state_manager.update_properties(
                            cid,
                            {"mfa_status": "enabled", "risk_score": max(ce.properties.get("risk_score", 0) - 3.0, 0)},
                            source="what_if_analysis",
                            description="MFA enabled for identity",
                        )

        if scenario.scenario_type == WhatIfScenarioType.NETWORK_SEGMENT:
            all_entities = state_manager.get_all_entities()
            iot_devices = [e for e in all_entities if e.category in (EntityCategory.IOT_DEVICE, EntityCategory.OT_DEVICE)]
            other_devices = [e for e in all_entities if e.category not in (EntityCategory.IOT_DEVICE, EntityCategory.OT_DEVICE)]

            iot_ids = {e.entity_id for e in iot_devices}
            for iot_entity in iot_devices:
                for conn_id in list(iot_entity.connected_entities):
                    if conn_id not in iot_ids:
                        await state_manager.remove_connection(iot_entity.entity_id, conn_id)

    def _compute_result(
        self,
        scenario: WhatIfScenario,
        baseline: SimulationReport,
        mitigated: SimulationReport,
    ) -> WhatIfResult:
        risk_reduction = baseline.risk_score - mitigated.risk_score
        impact_reduction = baseline.total_impact_score - mitigated.total_impact_score
        blast_radius_reduction = baseline.blast_radius_count - mitigated.blast_radius_count

        if baseline.risk_score > 0:
            effectiveness = min(risk_reduction / baseline.risk_score * 100, 100)
        else:
            effectiveness = 0.0

        analysis = {
            "baseline": {
                "risk_score": baseline.risk_score,
                "impact_score": baseline.total_impact_score,
                "blast_radius": baseline.blast_radius_count,
                "entities_compromised": baseline.entities_compromised,
                "success_rate": baseline.successful_steps / max(baseline.total_steps, 1),
            },
            "mitigated": {
                "risk_score": mitigated.risk_score,
                "impact_score": mitigated.total_impact_score,
                "blast_radius": mitigated.blast_radius_count,
                "entities_compromised": mitigated.entities_compromised,
                "success_rate": mitigated.successful_steps / max(mitigated.total_steps, 1),
            },
            "delta": {
                "risk_reduction": risk_reduction,
                "impact_reduction": impact_reduction,
                "blast_radius_reduction": blast_radius_reduction,
                "effectiveness": effectiveness,
            },
        }

        recommendations = []
        if effectiveness > 75:
            recommendations.append(f"Highly effective: {scenario.action} reduces risk by {effectiveness:.1f}% - implement immediately")
        elif effectiveness > 50:
            recommendations.append(f"Moderately effective: {scenario.action} reduces risk by {effectiveness:.1f}% - prioritize for implementation")
        elif effectiveness > 25:
            recommendations.append(f"Somewhat effective: {scenario.action} reduces risk by {effectiveness:.1f}% - consider as part of defense-in-depth")
        else:
            recommendations.append(f"Limited effectiveness: {scenario.action} only reduces risk by {effectiveness:.1f}% - may need additional controls")

        if mitigated.crown_jewels_affected:
            recommendations.append(f"Action reduces but does not eliminate crown jewel exposure ({len(mitigated.crown_jewels_affected)} still at risk)")

        if baseline.entities_compromised > mitigated.entities_compromised:
            recommendations.append(f"Reduces compromise reach from {baseline.entities_compromised} to {mitigated.entities_compromised} entities")

        summary = (
            f"Applying '{scenario.action}' to {scenario.target_entity_name} "
            f"reduces risk by {risk_reduction:.1f} points ({effectiveness:.1f}% effective), "
            f"reduces impact by {impact_reduction:.1f}, "
            f"and shrinks blast radius by {blast_radius_reduction} entities."
        )

        return WhatIfResult(
            result_id=str(uuid.uuid4()),
            scenario=scenario,
            baseline_report=baseline,
            mitigated_report=mitigated,
            risk_reduction=risk_reduction,
            impact_reduction=impact_reduction,
            blast_radius_reduction=blast_radius_reduction,
            effectiveness_score=effectiveness,
            analysis=analysis,
            recommendations=recommendations,
            summary=summary,
        )

    def get_result(self, result_id: str) -> Optional[WhatIfResult]:
        return self._results.get(result_id)

    def list_results(self) -> List[Dict[str, Any]]:
        return [r.to_dict() for r in self._results.values()]

    async def batch_analyze(
        self,
        scenarios: List[Tuple[WhatIfScenarioType, str]],
        attack_scenario_id: str = None,
    ) -> List[WhatIfResult]:
        results = []
        for scenario_type, target_id in scenarios:
            result = await self.analyze(scenario_type, target_id, attack_scenario_id=attack_scenario_id)
            results.append(result)
        return results


what_if_analyzer = WhatIfAnalyzer()
