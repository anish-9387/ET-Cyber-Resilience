from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from app.knowledge_graph.graph_manager import graph_manager
from app.knowledge_graph.graph_schema import NodeType, RelationshipType
from app.core.logger import logger


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class AttackPath:
    path: List[Dict[str, Any]]
    total_risk_score: float
    risk_level: RiskLevel
    steps: int
    crown_jewel_proximity: int
    description: str
    mitre_techniques: List[str] = field(default_factory=list)


@dataclass
class AttackPathAnalysis:
    paths: List[AttackPath]
    critical_paths: List[AttackPath]
    entry_points: List[str]
    crown_jewels: List[str]
    privilege_escalation_chains: List[List[str]]
    lateral_movement_paths: List[List[str]]
    summary: Dict[str, Any]


CROWN_JEWEL_LABELS = [NodeType.DATABASE.value, NodeType.IDENTITY.value]
CROWN_JEWEL_CRITICALITY = ["critical", "high"]

PRIVILEGE_ESCALATION_PATTERNS = [
    ("User", "Admin"),
    ("Admin", "Domain Admin"),
    ("Domain Admin", "Enterprise Admin"),
]

HIGH_RISK_RELATIONSHIPS = [
    RelationshipType.EXPLOITS.value,
    RelationshipType.TARGETS.value,
    RelationshipType.HAS_ACCOUNT.value,
]

LATERAL_MOVEMENT_RELATIONSHIPS = [
    RelationshipType.CONNECTED_TO.value,
    RelationshipType.CAN_REACH.value,
    RelationshipType.COMMUNICATES_WITH.value,
    RelationshipType.DEPENDS_ON.value,
]


class AttackPathAnalyzer:
    def __init__(self):
        self.graph = graph_manager

    async def find_all_paths(
        self,
        start_node_id: str,
        max_depth: int = 5,
        target_labels: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        query = """
        MATCH path = (start)-[*..%(max_depth)s]->(end)
        WHERE elementId(start) = $start_id
        %(target_filter)s
        RETURN
          [n in nodes(path) | elementId(n)] AS node_ids,
          [n in nodes(path) | labels(n)] AS node_labels,
          [n in nodes(path) | properties(n)] AS node_properties,
          [r in relationships(path) | type(r)] AS rel_types,
          [r in relationships(path) | properties(r)] AS rel_properties,
          length(path) AS depth
        ORDER BY depth ASC
        """
        target_filter = ""
        if target_labels:
            label_conditions = " OR ".join(
                f"'%(label)s' IN labels(end)" for label in target_labels
            )
            target_filter = f"AND ({label_conditions})"

        query = query % {"max_depth": max_depth, "target_filter": target_filter}
        return await self.graph.query(query, {"start_id": start_node_id})

    async def find_critical_paths(
        self,
        start_node_id: str,
        max_depth: int = 5
    ) -> List[AttackPath]:
        start_props = await self._get_node_properties(start_node_id)
        if not start_props:
            return []

        all_paths = await self.find_all_paths(
            start_node_id, max_depth, CROWN_JEWEL_LABELS
        )

        attack_paths = []
        for path_data in all_paths:
            risk_score = self._calculate_path_risk(path_data)
            proximity = self._calculate_crown_jewel_proximity(path_data)
            mitre_techniques = self._extract_mitre_techniques(path_data)
            risk_level = self._determine_risk_level(risk_score)

            attack_path = AttackPath(
                path=self._build_path_steps(path_data),
                total_risk_score=risk_score,
                risk_level=risk_level,
                steps=path_data["depth"],
                crown_jewel_proximity=proximity,
                description=self._generate_description(path_data, mitre_techniques),
                mitre_techniques=mitre_techniques,
            )
            attack_paths.append(attack_path)

        attack_paths.sort(key=lambda p: (-p.total_risk_score, p.steps))
        return attack_paths

    async def analyze(
        self,
        compromised_node_id: str,
        compromised_label: str,
        depth: int = 5
    ) -> AttackPathAnalysis:
        logger.info(
            "Starting attack path analysis",
            node_id=compromised_node_id,
            label=compromised_label
        )

        paths = await self.find_critical_paths(compromised_node_id, depth)

        entry_points = await self._identify_entry_points(compromised_node_id)

        crown_jewels = await self._identify_crown_jewels(compromised_node_id)

        priv_chains = await self._find_privilege_escalation_chains(compromised_node_id, depth)

        lateral_paths = await self._find_lateral_movement_paths(compromised_node_id, depth)

        critical_paths = [p for p in paths if p.risk_level in (RiskLevel.CRITICAL, RiskLevel.HIGH)]

        summary = {
            "total_paths_found": len(paths),
            "critical_paths": len(critical_paths),
            "max_risk_score": max((p.total_risk_score for p in paths), default=0.0),
            "avg_path_length": sum(p.steps for p in paths) / max(len(paths), 1),
            "entry_points_count": len(entry_points),
            "crown_jewels_at_risk": len(crown_jewels),
            "privilege_escalation_chains": len(priv_chains),
            "lateral_movement_paths": len(lateral_paths),
        }

        return AttackPathAnalysis(
            paths=paths,
            critical_paths=critical_paths,
            entry_points=entry_points,
            crown_jewels=crown_jewels,
            privilege_escalation_chains=priv_chains,
            lateral_movement_paths=lateral_paths,
            summary=summary,
        )

    async def get_blast_radius_analysis(self, node_id: str, depth: int = 3) -> Dict[str, Any]:
        blast = await self.graph.get_blast_radius(node_id, depth)

        affected_assets = []
        affected_departments = set()
        risk_score = 0.0

        for item in blast["blast_radius"]:
            props = dict(item["node"])
            types = item["type"]
            entity = {"properties": props, "labels": types}

            if "Department" in types:
                affected_departments.add(props.get("name", "unknown"))

            if props.get("criticality") == "critical":
                risk_score += 10.0
            elif props.get("criticality") == "high":
                risk_score += 5.0

            affected_assets.append(entity)

        return {
            "blast_radius": affected_assets,
            "total_count": blast["total_count"],
            "affected_departments": list(affected_departments),
            "risk_score": risk_score,
            "risk_level": self._determine_risk_level(risk_score).value,
            "depth": depth,
        }

    async def _get_node_properties(self, node_id: str) -> Optional[Dict]:
        result = await self.graph.query(
            "MATCH (n) WHERE elementId(n) = $id RETURN properties(n) as props",
            {"id": node_id}
        )
        return result[0]["props"] if result else None

    def _calculate_path_risk(self, path_data: Dict[str, Any]) -> float:
        risk_score = 0.0
        rel_types = path_data.get("rel_types", [])
        node_labels = path_data.get("node_labels", [])
        node_props = path_data.get("node_properties", [])

        for rel in rel_types:
            if rel in HIGH_RISK_RELATIONSHIPS:
                risk_score += 8.0
            if rel in LATERAL_MOVEMENT_RELATIONSHIPS:
                risk_score += 3.0

        for labels, props in zip(node_labels, node_props):
            if "CVE" in labels and props.get("cvss_score"):
                risk_score += float(props["cvss_score"]) / 2.0
            if "ThreatActor" in labels:
                risk_score += 5.0
            criticality = props.get("criticality", "")
            if criticality == "critical":
                risk_score += 5.0
            elif criticality == "high":
                risk_score += 3.0

        risk_score += len(rel_types) * 1.0

        return min(risk_score, 100.0)

    def _calculate_crown_jewel_proximity(self, path_data: Dict[str, Any]) -> int:
        node_labels = path_data.get("node_labels", [])
        for i, labels in enumerate(reversed(node_labels)):
            for label in CROWN_JEWEL_LABELS:
                if label in labels:
                    return i
        return len(node_labels)

    def _extract_mitre_techniques(self, path_data: Dict[str, Any]) -> List[str]:
        mitre_techniques = []
        node_labels = path_data.get("node_labels", [])
        node_props = path_data.get("node_properties", [])
        for labels, props in zip(node_labels, node_props):
            if "MITRETechnique" in labels:
                technique_id = props.get("technique_id", "")
                technique_name = props.get("name", "")
                if technique_id:
                    mitre_techniques.append(f"{technique_id}: {technique_name}")
        return mitre_techniques

    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        if risk_score >= 70:
            return RiskLevel.CRITICAL
        elif risk_score >= 40:
            return RiskLevel.HIGH
        elif risk_score >= 20:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW

    def _build_path_steps(self, path_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        steps = []
        node_ids = path_data.get("node_ids", [])
        node_labels = path_data.get("node_labels", [])
        node_props = path_data.get("node_properties", [])
        rel_types = path_data.get("rel_types", [])
        rel_props = path_data.get("rel_properties", [])

        for i, node_id in enumerate(node_ids):
            step = {
                "node_id": node_id,
                "labels": node_labels[i] if i < len(node_labels) else [],
                "properties": node_props[i] if i < len(node_props) else {},
            }
            if i > 0 and i - 1 < len(rel_types):
                step["incoming_rel"] = {
                    "type": rel_types[i - 1],
                    "properties": rel_props[i - 1] if i - 1 < len(rel_props) else {},
                }
            steps.append(step)
        return steps

    def _generate_description(
        self, path_data: Dict[str, Any], mitre_techniques: List[str]
    ) -> str:
        node_labels = path_data.get("node_labels", [])
        node_props = path_data.get("node_properties", [])
        rel_types = path_data.get("rel_types", [])

        parts = []
        for i, (labels, props) in enumerate(zip(node_labels, node_props)):
            name = props.get("hostname") or props.get("name") or props.get("username") or labels[0] if labels else "unknown"
            parts.append(name)
            if i < len(rel_types):
                parts.append(f"--[{rel_types[i]}]-->")

        path_str = " ".join(parts)

        techniques = ", ".join(mitre_techniques[:3]) if mitre_techniques else "None identified"

        return f"Attack path: {path_str} | MITRE techniques: {techniques}"

    async def _identify_entry_points(self, node_id: str) -> List[str]:
        result = await self.graph.query(
            """
            MATCH (start) WHERE elementId(start) = $start_id
            MATCH (start)-[:EXPLOITS|TARGETS*1..2]->(entry)
            RETURN DISTINCT elementId(entry) AS entry_id,
                   labels(entry) AS labels,
                   entry.name AS name
            """,
            {"start_id": node_id}
        )
        entries = []
        for record in result:
            name = record.get("name") or record["labels"][0] if record.get("labels") else "unknown"
            entries.append(f"{record['entry_id']} ({name})")
        return entries

    async def _identify_crown_jewels(self, node_id: str) -> List[str]:
        result = await self.graph.query(
            """
            MATCH (start) WHERE elementId(start) = $start_id
            MATCH path = shortestPath((start)-[*..5]-(cj))
            WHERE labels(cj) IN $jewel_labels
               OR cj.criticality IN $jewel_criticality
            RETURN DISTINCT elementId(cj) AS jewel_id,
                   labels(cj) AS labels,
                   cj.name AS name,
                   cj.criticality AS criticality,
                   length(path) AS distance
            ORDER BY distance ASC
            """,
            {
                "start_id": node_id,
                "jewel_labels": CROWN_JEWEL_LABELS,
                "jewel_criticality": CROWN_JEWEL_CRITICALITY,
            }
        )
        jewels = []
        for record in result:
            name = record.get("name") or record["labels"][0] if record.get("labels") else "unknown"
            jewels.append(f"{record['jewel_id']} ({name}) - {record.get('criticality', 'unknown')}")
        return jewels

    async def _find_privilege_escalation_chains(
        self, node_id: str, max_depth: int = 5
    ) -> List[List[str]]:
        result = await self.graph.query(
            """
            MATCH path = (start)-[:HAS_ACCOUNT|CONTROLS|CAN_ACCESS*..%(max_depth)s]->(target)
            WHERE elementId(start) = $start_id
            RETURN [n in nodes(path) | elementId(n)] AS node_ids,
                   [n in nodes(path) | labels(n)] AS node_labels,
                   [r in relationships(path) | type(r)] AS rel_types,
                   [n in nodes(path) | n.privilege_level] AS privilege_levels
            """ % {"max_depth": max_depth},
            {"start_id": node_id}
        )
        chains = []
        for record in result:
            levels = record.get("privilege_levels", [])
            if any(lv in ["admin", "critical", "Domain Admin"] for lv in levels if lv):
                chain = []
                for i, node_id_el in enumerate(record["node_ids"]):
                    label = record["node_labels"][i][0] if record["node_labels"][i] else "?"
                    chain.append(f"{node_id_el} ({label})")
                chains.append(chain)
        return chains

    async def _find_lateral_movement_paths(
        self, node_id: str, max_depth: int = 5
    ) -> List[List[str]]:
        result = await self.graph.query(
            """
            MATCH path = (start)-[:CONNECTED_TO|COMMUNICATES_WITH|CAN_REACH|DEPENDS_ON*..%(max_depth)s]->(target)
            WHERE elementId(start) = $start_id
              AND elementId(start) <> elementId(target)
            RETURN [n in nodes(path) | elementId(n)] AS node_ids,
                   [n in nodes(path) | labels(n)] AS node_labels,
                   [n in nodes(path) | n.hostname] AS hostnames
            """ % {"max_depth": max_depth},
            {"start_id": node_id}
        )
        paths = []
        seen = set()
        for record in result:
            key = "->".join(record["node_ids"])
            if key not in seen:
                seen.add(key)
                path = []
                for i, node_id_el in enumerate(record["node_ids"]):
                    hostname = record["hostnames"][i] or ""
                    label = record["node_labels"][i][0] if record["node_labels"][i] else "?"
                    path.append(f"{node_id_el} ({label}) [{hostname}]" if hostname else f"{node_id_el} ({label})")
                paths.append(path)
        return paths


attack_path_analyzer = AttackPathAnalyzer()
