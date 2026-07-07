from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field, asdict
import uuid
import asyncio
from app.core.logger import logger
from app.digital_twin.state_manager import (
    state_manager,
    EntityState,
    EntityCategory,
    EntityStatus,
)
from app.knowledge_graph.graph_manager import graph_manager


class SimulationStepType(str, Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


@dataclass
class SimulationStep:
    step_id: str
    step_type: SimulationStepType
    name: str
    description: str
    target_entity_id: str
    target_entity_name: str
    technique_id: Optional[str] = None
    success_probability: float = 0.5
    succeeded: bool = False
    impact_score: float = 0.0
    affected_entities: List[str] = field(default_factory=list)
    detection_chance: float = 0.0
    detected: bool = False
    mitigations: List[str] = field(default_factory=list)
    outputs: Dict[str, Any] = field(default_factory=dict)
    duration_seconds: int = 0
    mitre_mapping: Optional[str] = None


@dataclass
class SimulationScenario:
    scenario_id: str
    name: str
    description: str
    attack_type: str
    starting_entity_id: str
    starting_entity_name: str
    steps: List[SimulationStep] = field(default_factory=list)
    threat_actor: Optional[str] = None
    difficulty: str = "medium"
    estimated_duration_minutes: int = 30
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SimulationReport:
    report_id: str
    scenario: SimulationScenario
    timestamp: str
    duration_seconds: float
    overall_success: bool
    total_impact_score: float
    blast_radius_count: int
    entities_compromised: int
    detections_made: int
    successful_steps: int
    total_steps: int
    risk_score: float
    critical_findings: List[Dict[str, Any]] = field(default_factory=list)
    recommended_mitigations: List[str] = field(default_factory=list)
    step_results: List[Dict[str, Any]] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    crown_jewels_affected: List[str] = field(default_factory=list)
    chain_of_compromise: List[str] = field(default_factory=list)
    mitre_technique_coverage: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "scenario_id": self.scenario.scenario_id,
            "scenario_name": self.scenario.name,
            "timestamp": self.timestamp,
            "duration_seconds": self.duration_seconds,
            "overall_success": self.overall_success,
            "total_impact_score": self.total_impact_score,
            "blast_radius_count": self.blast_radius_count,
            "entities_compromised": self.entities_compromised,
            "detections_made": self.detections_made,
            "successful_steps": self.successful_steps,
            "total_steps": self.total_steps,
            "risk_score": self.risk_score,
            "critical_findings": self.critical_findings,
            "recommended_mitigations": self.recommended_mitigations,
            "crown_jewels_affected": self.crown_jewels_affected,
            "chain_of_compromise": self.chain_of_compromise,
            "mitre_technique_coverage": self.mitre_technique_coverage,
        }


RANSOMWARE_SCENARIO_TEMPLATE = {
    "scenario_id": "scenario-ransomware-001",
    "name": "Ransomware Attack on Hospital Network",
    "description": "Simulates a LockBit ransomware attack starting from a phishing email, moving laterally through the hospital network, encrypting EHR databases and medical systems.",
    "attack_type": "ransomware",
    "steps": [
        SimulationStep(
            step_id="step-001", step_type=SimulationStepType.INITIAL_ACCESS,
            name="Phishing Email", description="Attacker sends spear-phishing email with malicious attachment to hospital staff",
            technique_id="T1566", mitre_mapping="T1566.001",
            success_probability=0.7, detection_chance=0.3, duration_seconds=30,
            mitigations=["Email filtering", "Security awareness training", "DMARC/DKIM"],
        ),
        SimulationStep(
            step_id="step-002", step_type=SimulationStepType.EXECUTION,
            name="Malicious Macro Execution", description="User opens attachment and executes malicious macro",
            technique_id="T1204", mitre_mapping="T1204.002",
            success_probability=0.8, detection_chance=0.2, duration_seconds=10,
            mitigations=["Macro security policies", "Application allowlisting", "ASR rules"],
        ),
        SimulationStep(
            step_id="step-003", step_type=SimulationStepType.PRIVILEGE_ESCALATION,
            name="Local Privilege Escalation", description="Exploit local vulnerability to gain admin rights on workstation",
            technique_id="T1068", mitre_mapping="T1068",
            success_probability=0.85, detection_chance=0.15, duration_seconds=60,
            mitigations=["Patch management", "Least privilege", "Credential Guard"],
        ),
        SimulationStep(
            step_id="step-004", step_type=SimulationStepType.CREDENTIAL_ACCESS,
            name="Credential Dumping", description="Dump LSASS memory to extract domain credentials",
            technique_id="T1003", mitre_mapping="T1003.001",
            success_probability=0.75, detection_chance=0.25, duration_seconds=120,
            mitigations=["Credential Guard", "LSA protection", "EDR monitoring"],
        ),
        SimulationStep(
            step_id="step-005", step_type=SimulationStepType.LATERAL_MOVEMENT,
            name="Lateral Movement via RDP", description="Use stolen credentials to move laterally to file server",
            technique_id="T1021", mitre_mapping="T1021.001",
            success_probability=0.8, detection_chance=0.3, duration_seconds=180,
            mitigations=["Network segmentation", "RDP restriction", "MFA for RDP"],
        ),
        SimulationStep(
            step_id="step-006", step_type=SimulationStepType.DISCOVERY,
            name="Network Discovery", description="Enumerate network shares, domain controllers, and database servers",
            technique_id="T1049", mitre_mapping="T1049",
            success_probability=0.9, detection_chance=0.2, duration_seconds=60,
            mitigations=["Network monitoring", "Segment discovery traffic", "Host firewall"],
        ),
        SimulationStep(
            step_id="step-007", step_type=SimulationStepType.LATERAL_MOVEMENT,
            name="Lateral Movement to Database Server", description="Move from file server to database server using cached credentials",
            technique_id="T1021", mitre_mapping="T1021.004",
            success_probability=0.7, detection_chance=0.4, duration_seconds=300,
            mitigations=["Jump server requirement", "Database firewall", "Network micro-segmentation"],
        ),
        SimulationStep(
            step_id="step-008", step_type=SimulationStepType.COLLECTION,
            name="Database Exfiltration", description="Extract patient records from EHR database",
            technique_id="T1530", mitre_mapping="T1530",
            success_probability=0.8, detection_chance=0.5, duration_seconds=600,
            mitigations=["Database encryption", "Data loss prevention", "Audit logging"],
        ),
        SimulationStep(
            step_id="step-009", step_type=SimulationStepType.IMPACT,
            name="File Encryption", description="Deploy ransomware to encrypt file shares, databases, and backups",
            technique_id="T1486", mitre_mapping="T1486",
            success_probability=0.9, detection_chance=0.6, duration_seconds=900,
            mitigations=["Offline backups", "Immutable storage", "Ransomware rollback"],
        ),
        SimulationStep(
            step_id="step-010", step_type=SimulationStepType.IMPACT,
            name="Service Disruption", description="Critical healthcare services disrupted due to encrypted systems",
            technique_id="T1489", mitre_mapping="T1489",
            success_probability=0.95, detection_chance=0.8, duration_seconds=120,
            mitigations=["Business continuity plan", "Disaster recovery", "System redundancy"],
        ),
    ],
}

SUPPLY_CHAIN_SCENARIO_TEMPLATE = {
    "scenario_id": "scenario-supplychain-001",
    "name": "Supply Chain Attack via Medical Device Firmware",
    "description": "Simulates compromise through vulnerable medical device firmware update mechanism allowing attacker access to hospital network.",
    "attack_type": "supply_chain",
    "steps": [
        SimulationStep(
            step_id="sc-step-001", step_type=SimulationStepType.INITIAL_ACCESS,
            name="Firmware Backdoor", description="Compromised firmware update for MRI scanner contains backdoor",
            technique_id="T1195", mitre_mapping="T1195.001",
            success_probability=0.6, detection_chance=0.1, duration_seconds=3600,
            mitigations=["Firmware signing", "Vendor assessment", "Software Bill of Materials"],
        ),
        SimulationStep(
            step_id="sc-step-002", step_type=SimulationStepType.EXECUTION,
            name="Device Compromise", description="Backdoor executed on MRI scanner providing initial foothold",
            technique_id="T1203", mitre_mapping="T1203",
            success_probability=0.8, detection_chance=0.2, duration_seconds=300,
            mitigations=["Device segmentation", "Medical device monitoring", "Network access control"],
        ),
        SimulationStep(
            step_id="sc-step-003", step_type=SimulationStepType.LATERAL_MOVEMENT,
            name="Pivot to PACS Server", description="From compromised MRI, move laterally to PACS server via DICOM protocol",
            technique_id="T1021", mitre_mapping="T1021",
            success_probability=0.7, detection_chance=0.3, duration_seconds=600,
            mitigations=["DICOM security controls", "Protocol filtering", "Medical VLAN isolation"],
        ),
        SimulationStep(
            step_id="sc-step-004", step_type=SimulationStepType.COLLECTION,
            name="Medical Data Theft", description="Exfiltrate medical images and patient data from PACS",
            technique_id="T1530", mitre_mapping="T1530",
            success_probability=0.85, detection_chance=0.4, duration_seconds=1200,
            mitigations=["Data encryption at rest", "Access monitoring", "Anomaly detection"],
        ),
    ],
}


class SimulationEngine:
    def __init__(self):
        self._scenarios: Dict[str, SimulationScenario] = {}
        self._reports: Dict[str, SimulationReport] = {}
        self._load_default_scenarios()

    def _load_default_scenarios(self):
        scenario_data = RANSOMWARE_SCENARIO_TEMPLATE.copy()
        scenario_data["steps"] = [
            SimulationStep(**s) if isinstance(s, dict) else s
            for s in scenario_data["steps"]
        ]
        ransomware = SimulationScenario(**scenario_data)
        self._scenarios[ransomware.scenario_id] = ransomware

        sc_data = SUPPLY_CHAIN_SCENARIO_TEMPLATE.copy()
        sc_data["steps"] = [
            SimulationStep(**s) if isinstance(s, dict) else s
            for s in sc_data["steps"]
        ]
        supply_chain = SimulationScenario(**sc_data)
        self._scenarios[supply_chain.scenario_id] = supply_chain

    async def run_scenario(
        self,
        scenario: SimulationScenario,
        step_delay_ms: int = 100,
    ) -> SimulationReport:
        logger.info("Starting simulation", scenario=scenario.name)

        start_time = datetime.now(timezone.utc)
        step_results = []
        timeline = []
        total_impact = 0.0
        successful_steps = 0
        detections_made = 0
        all_affected = set()
        compromised_entities = set()
        chain_of_compromise = [scenario.starting_entity_name]

        for step in scenario.steps:
            await asyncio.sleep(step_delay_ms / 1000.0)

            step_result = await self._execute_step(step, scenario)
            step_results.append(step_result)
            total_impact += step_result["impact_score"]

            timeline.append({
                "step_id": step.step_id,
                "time_offset_seconds": sum(s.duration_seconds for s in scenario.steps[:scenario.steps.index(step)]),
                "step_name": step.name,
                "succeeded": step_result["succeeded"],
                "detected": step_result["detected"],
                "target": step_result["target_name"],
            })

            if step_result["succeeded"]:
                successful_steps += 1
                compromised_entities.add(step_result["target_entity_id"])
                chain_of_compromise.append(step_result["target_name"])

            if step_result["detected"]:
                detections_made += 1

            all_affected.update(step_result.get("affected_entities", []))
            all_affected.add(step_result["target_entity_id"])

            if step_result["succeeded"]:
                await state_manager.update_status(
                    step_result["target_entity_id"],
                    EntityStatus.COMPROMISED,
                    source=f"simulation:{scenario.scenario_id}",
                    description=f"Step {step.step_id}: {step.name}",
                    propagate=True,
                )

        end_time = datetime.now(timezone.utc)
        duration = (end_time - start_time).total_seconds()

        overall_success = successful_steps == len(scenario.steps)

        risk_score = self._calculate_risk_score(
            successful_steps, len(scenario.steps), total_impact, detections_made
        )

        critical_findings = self._generate_critical_findings(
            step_results, scenario
        )

        recommended_mitigations = self._aggregate_mitigations(scenario)

        crown_jewels = await self._identify_affected_crown_jewels(compromised_entities)

        mitre_coverage = list(set(
            s.mitre_mapping or s.technique_id for s in scenario.steps if s.mitre_mapping or s.technique_id
        ))

        report = SimulationReport(
            report_id=str(uuid.uuid4()),
            scenario=scenario,
            timestamp=end_time.isoformat(),
            duration_seconds=duration,
            overall_success=overall_success,
            total_impact_score=total_impact,
            blast_radius_count=len(all_affected),
            entities_compromised=len(compromised_entities),
            detections_made=detections_made,
            successful_steps=successful_steps,
            total_steps=len(scenario.steps),
            risk_score=risk_score,
            critical_findings=critical_findings,
            recommended_mitigations=recommended_mitigations,
            step_results=step_results,
            timeline=timeline,
            crown_jewels_affected=crown_jewels,
            chain_of_compromise=chain_of_compromise,
            mitre_technique_coverage=mitre_coverage,
        )

        self._reports[report.report_id] = report
        logger.info("Simulation complete", report_id=report.report_id, risk_score=risk_score)
        return report

    async def _execute_step(
        self,
        step: SimulationStep,
        scenario: SimulationScenario,
    ) -> Dict[str, Any]:
        entity = state_manager.get_entity(step.target_entity_id)

        if not entity:
            logger.warning("Target entity not found in twin state", target=step.target_entity_id)
            return {
                "step_id": step.step_id,
                "step_name": step.name,
                "succeeded": False,
                "success_probability": step.success_probability,
                "detected": False,
                "impact_score": 0.0,
                "target_entity_id": step.target_entity_id,
                "target_name": step.target_entity_name,
                "affected_entities": [],
                "message": "Target entity not found",
            }

        import random
        succeeded = random.random() < step.success_probability
        detected = random.random() < step.detection_chance if succeeded else False

        blast = await graph_manager.get_blast_radius(step.target_entity_id, depth=2)
        affected = [item["node"].element_id for item in blast["blast_radius"]]

        impact_base = {
            SimulationStepType.INITIAL_ACCESS: 3.0,
            SimulationStepType.EXECUTION: 5.0,
            SimulationStepType.PERSISTENCE: 4.0,
            SimulationStepType.PRIVILEGE_ESCALATION: 8.0,
            SimulationStepType.DEFENSE_EVASION: 6.0,
            SimulationStepType.CREDENTIAL_ACCESS: 9.0,
            SimulationStepType.DISCOVERY: 2.0,
            SimulationStepType.LATERAL_MOVEMENT: 7.0,
            SimulationStepType.COLLECTION: 8.0,
            SimulationStepType.COMMAND_AND_CONTROL: 5.0,
            SimulationStepType.EXFILTRATION: 10.0,
            SimulationStepType.IMPACT: 10.0,
        }
        impact_score = impact_base.get(step.step_type, 5.0) * (1.0 if succeeded else 0.0)

        return {
            "step_id": step.step_id,
            "step_name": step.name,
            "step_type": step.step_type.value,
            "succeeded": succeeded,
            "success_probability": step.success_probability,
            "detected": detected,
            "detection_chance": step.detection_chance,
            "impact_score": impact_score,
            "target_entity_id": step.target_entity_id,
            "target_name": step.target_entity_name,
            "affected_entities": affected,
            "message": f"Step '{step.name}' {'succeeded' if succeeded else 'failed'} (detected: {detected})",
            "mitigations_applied": [],
        }

    def _calculate_risk_score(
        self, successful: int, total: int, impact: float, detections: int
    ) -> float:
        success_rate = successful / max(total, 1)
        detection_rate = detections / max(successful, 1)
        impact_factor = min(impact / 100.0, 1.0)
        risk = (success_rate * 0.5 + (1 - detection_rate) * 0.2 + impact_factor * 0.3) * 100
        return min(risk, 100.0)

    def _generate_critical_findings(
        self, step_results: List[Dict[str, Any]], scenario: SimulationScenario
    ) -> List[Dict[str, Any]]:
        findings = []
        for result in step_results:
            if result["succeeded"] and result["impact_score"] >= 8.0:
                findings.append({
                    "severity": "critical",
                    "step": result["step_name"],
                    "description": f"Critical step '{result['step_name']}' succeeded with high impact",
                    "impact_score": result["impact_score"],
                    "detected": result["detected"],
                })
        return findings

    def _aggregate_mitigations(self, scenario: SimulationScenario) -> List[str]:
        mitigations = set()
        for step in scenario.steps:
            for mitigation in step.mitigations:
                mitigations.add(mitigation)
        return list(mitigations)

    async def _identify_affected_crown_jewels(
        self, compromised_ids: Set[str]
    ) -> List[str]:
        crown_jewels = []
        for entity_id in compromised_ids:
            entity = state_manager.get_entity(entity_id)
            if entity:
                criticality = entity.properties.get("criticality", "")
                if criticality in ("critical", "high"):
                    crown_jewels.append(
                        entity.properties.get("name") or entity.properties.get("hostname") or entity_id
                    )
        return crown_jewels

    def get_scenario(self, scenario_id: str) -> Optional[SimulationScenario]:
        return self._scenarios.get(scenario_id)

    def list_scenarios(self) -> List[Dict[str, Any]]:
        return [
            {
                "scenario_id": s.scenario_id,
                "name": s.name,
                "description": s.description,
                "attack_type": s.attack_type,
                "steps": len(s.steps),
                "difficulty": s.difficulty,
            }
            for s in self._scenarios.values()
        ]

    def register_scenario(self, scenario: SimulationScenario):
        self._scenarios[scenario.scenario_id] = scenario

    def get_report(self, report_id: str) -> Optional[SimulationReport]:
        return self._reports.get(report_id)

    def list_reports(self) -> List[Dict[str, Any]]:
        return [
            {
                "report_id": r.report_id,
                "scenario_name": r.scenario.name,
                "timestamp": r.timestamp,
                "risk_score": r.risk_score,
                "overall_success": r.overall_success,
                "duration_seconds": r.duration_seconds,
            }
            for r in self._reports.values()
        ]


simulation_engine = SimulationEngine()
