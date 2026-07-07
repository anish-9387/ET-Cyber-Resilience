from typing import Dict, Any, Optional, List, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
from app.agents.base_agent import BaseAgent
from app.core.logger import logger
from app.core.database import neo4j_driver
from app.core.llm import llm_manager
import json, hashlib


class TwinAsset:
    def __init__(self, asset_id: str, asset_type: str, properties: Dict[str, Any]):
        self.asset_id = asset_id
        self.asset_type = asset_type
        self.properties = properties
        self.relationships: List[Tuple[str, str, Dict]] = []
        self.criticality: int = properties.get("criticality", 3)
        self.last_sync: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "asset_type": self.asset_type,
            "properties": self.properties,
            "criticality": self.criticality,
            "last_sync": self.last_sync.isoformat() if self.last_sync else None,
        }


class DigitalTwinAgent(BaseAgent):
    def __init__(self, version: str = "1.0.0"):
        super().__init__(
            name="digital_twin_agent",
            agent_type="digital_twin",
            version=version,
        )
        self.assets: Dict[str, TwinAsset] = {}
        self.graph_adjacency: Dict[str, Dict[str, List[str]]] = defaultdict(lambda: defaultdict(list))

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        self.last_run = datetime.utcnow()
        action = input_data.get("action", "query")

        try:
            if action == "register_asset":
                return await self._register_asset(input_data)
            elif action == "sync_from_graph":
                return await self._sync_from_graph(input_data)
            elif action == "query":
                return await self._query(input_data)
            elif action == "simulate":
                return await self._simulate(input_data)
            elif action == "attack_path":
                return await self._attack_path_analysis(input_data)
            elif action == "red_team":
                return await self._red_team_simulation(input_data)
            elif action == "blue_team":
                return await self._blue_team_testing(input_data)
            elif action == "what_if":
                return await self._what_if(input_data)
            elif action == "add_relationship":
                return self._add_relationship(input_data)
            elif action == "get_asset":
                return self._get_asset(input_data)
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        except Exception as e:
            logger.error(f"DigitalTwinAgent error", error=str(e))
            self.update_metrics(False)
            return {"success": False, "error": str(e)}

    async def _register_asset(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = input_data.get("asset_id")
        asset_type = input_data.get("asset_type", "unknown")
        properties = input_data.get("properties", {})

        if not asset_id:
            return {"success": False, "error": "asset_id required"}

        if asset_id not in self.assets:
            self.assets[asset_id] = TwinAsset(asset_id, asset_type, properties)
            self.graph_adjacency[asset_id]
        else:
            self.assets[asset_id].properties.update(properties)
            self.assets[asset_id].asset_type = asset_type

        self.assets[asset_id].last_sync = datetime.utcnow()

        relationships = input_data.get("relationships", [])
        for rel in relationships:
            target = rel.get("target")
            rel_type = rel.get("type", "connected_to")
            rel_props = rel.get("properties", {})
            if target:
                self._add_relationship_internal(asset_id, target, rel_type, rel_props)

        await self.publish_event("digital_twin.asset_registered", {
            "asset_id": asset_id,
            "asset_type": asset_type,
        })

        return {"success": True, "asset": self.assets[asset_id].to_dict()}

    async def _sync_from_graph(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        try:
            async with neo4j_driver.session() as session:
                result = await session.run(
                    "MATCH (n) OPTIONAL MATCH (n)-[r]->(m) "
                    "RETURN n, collect({rel: type(r), target: m.id}) AS relationships"
                )
                records = await result.fetch()

                synced_count = 0
                for record in records:
                    node = record["n"]
                    asset_id = node.get("id", node.get("name", str(hash(str(node)))))
                    asset_type = list(node.labels)[0] if node.labels else "unknown"
                    props = dict(node)

                    if asset_id not in self.assets:
                        self.assets[asset_id] = TwinAsset(asset_id, asset_type, props)
                        self.assets[asset_id].last_sync = datetime.utcnow()
                        synced_count += 1

                    for rel in record.get("relationships", []):
                        target = rel.get("target")
                        rel_type = rel.get("rel", "related_to")
                        if target:
                            self._add_relationship_internal(asset_id, str(target), str(rel_type), {})

            return {"success": True, "synced_count": synced_count, "total_assets": len(self.assets)}

        except Exception as e:
            logger.warning(f"Neo4j sync failed, using in-memory graph", error=str(e))
            return {"success": True, "synced_count": 0, "total_assets": len(self.assets), "mode": "in_memory"}

    async def _query(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        query_type = input_data.get("query_type", "asset")
        filters = input_data.get("filters", {})

        if query_type == "asset":
            asset_id = input_data.get("asset_id")
            if asset_id:
                return self._get_asset(input_data)
            return self._list_assets(filters)

        elif query_type == "path":
            source = input_data.get("source")
            target = input_data.get("target")
            if source and target:
                path = self._find_path(source, target)
                return {"success": True, "path": path, "hops": len(path) - 1 if path else 0}
            return {"success": False, "error": "source and target required"}

        elif query_type == "neighbors":
            asset_id = input_data.get("asset_id")
            depth = input_data.get("depth", 1)
            if asset_id:
                neighbors = self._get_neighbors(asset_id, depth)
                return {"success": True, "asset_id": asset_id, "neighbors": neighbors}
            return {"success": False, "error": "asset_id required"}

        elif query_type == "exposure":
            asset_id = input_data.get("asset_id")
            if asset_id:
                exposure = self._calculate_exposure(asset_id)
                return {"success": True, "exposure": exposure}
            return {"success": False, "error": "asset_id required"}

        return {"success": False, "error": f"Unknown query_type: {query_type}"}

    async def _simulate(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        scenario = input_data.get("scenario", "compromise")
        target_asset = input_data.get("target_asset")
        attacker_capability = input_data.get("attacker_capability", "medium")

        if not target_asset or target_asset not in self.assets:
            return {"success": False, "error": f"Target asset '{target_asset}' not found in digital twin"}

        if scenario == "compromise":
            return self._simulate_compromise(target_asset, attacker_capability)
        elif scenario == "ransomware":
            return self._simulate_ransomware(target_asset)
        elif scenario == "data_breach":
            return self._simulate_data_breach(target_asset)
        elif scenario == "lateral_movement":
            return self._simulate_lateral_movement(target_asset, attacker_capability)
        elif scenario == "privilege_escalation":
            return self._simulate_privilege_escalation(target_asset)
        else:
            return {"success": False, "error": f"Unknown scenario: {scenario}"}

    async def _attack_path_analysis(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        start_asset = input_data.get("start_asset")
        target_asset = input_data.get("target_asset")
        max_depth = input_data.get("max_depth", 5)

        if not start_asset or not target_asset:
            return {"success": False, "error": "start_asset and target_asset required"}

        if start_asset not in self.assets or target_asset not in self.assets:
            return {"success": False, "error": "One or both assets not found"}

        paths = self._find_all_paths(start_asset, target_asset, max_depth)

        scored_paths = []
        for path in paths:
            score = self._score_attack_path(path)
            scored_paths.append({
                "path": path,
                "hops": len(path) - 1,
                "risk_score": score,
                "critical_assets_affected": [n for n in path if self.assets.get(n, TwinAsset("", "", {})).criticality >= 4],
            })

        scored_paths.sort(key=lambda x: -x["risk_score"])

        return {
            "success": True,
            "start_asset": start_asset,
            "target_asset": target_asset,
            "total_paths": len(scored_paths),
            "paths": scored_paths,
            "most_risky_path": scored_paths[0] if scored_paths else None,
        }

    async def _red_team_simulation(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        objective = input_data.get("objective", "domain_admin")
        start_points = input_data.get("start_points", [])
        constraints = input_data.get("constraints", {})

        if not start_points:
            start_points = self._find_initial_access_points()

        results = []
        for start in start_points:
            if start not in self.assets:
                continue
            paths = self._find_paths_to_objective(start, objective)
            if paths:
                results.append({
                    "entry_point": start,
                    "possible": True,
                    "paths": paths[:3],
                    "estimated_time_minutes": len(paths[0]) * 15 if paths else 0,
                })
            else:
                results.append({"entry_point": start, "possible": False})

        return {
            "success": True,
            "objective": objective,
            "simulation_type": "red_team",
            "entry_points_analyzed": len(start_points),
            "successful_paths": sum(1 for r in results if r["possible"]),
            "results": results,
        }

    async def _blue_team_testing(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        defense_controls = input_data.get("defenses", [])
        simulation_type = input_data.get("simulation_type", "breach")

        if simulation_type == "breach":
            return self._test_defense_controls(defense_controls)
        elif simulation_type == "detection":
            return self._test_detection_capabilities(defense_controls)
        else:
            return {"success": False, "error": f"Unknown simulation_type: {simulation_type}"}

    async def _what_if(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        question = input_data.get("question", "")
        asset_id = input_data.get("asset_id")
        scenario = input_data.get("scenario", {})

        if asset_id and not question:
            question = f"If attacker compromises {asset_id}"
            if scenario:
                question += f" with {json.dumps(scenario)}"

        if "compromise" in question.lower() or asset_id:
            target = asset_id or self._extract_asset_from_question(question)
            if target and target in self.assets:
                return self._simulate_compromise_consequences(target, question)

        return await self._llm_what_if(question, scenario)

    async def _llm_what_if(self, question: str, scenario: Dict[str, Any]) -> Dict[str, Any]:
        try:
            context = f"Digital Twin Assets: {json.dumps({aid: a.to_dict() for aid, a in list(self.assets.items())[:20]})}"
            prompt = f"""Question: {question}
Scenario: {json.dumps(scenario)}
Context: {context}

Provide a detailed what-if analysis for this cybersecurity scenario based on the digital twin. Include:
1. Immediate impact
2. Cascading failures
3. Blast radius
4. Recommended mitigations"""
            result = await llm_manager.generate(prompt)
            return {
                "success": True,
                "question": question,
                "analysis": result,
                "source": "llm",
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "success": True,
                "question": question,
                "analysis": "Could not generate analysis via LLM. Provide more detailed scenario parameters.",
                "source": "fallback",
            }

    def _simulate_compromise(self, asset_id: str, capability: str) -> Dict[str, Any]:
        asset = self.assets[asset_id]
        reachable = self._get_neighbors(asset_id, depth=3)
        critical_affected = [n for n in reachable if self.assets.get(n, TwinAsset("", "", {})).criticality >= 4]

        capability_factors = {"low": 0.3, "medium": 0.6, "high": 0.9}
        factor = capability_factors.get(capability, 0.6)

        return {
            "success": True,
            "scenario": "compromise",
            "target": asset.to_dict(),
            "compromise_probability": round(factor, 2),
            "immediate_impact": {
                "assets_directly_reachable": len(reachable),
                "critical_assets_at_risk": len(critical_affected),
                "critical_assets_list": critical_affected,
            },
            "estimated_dwell_time_minutes": int(30 / factor),
            "lateral_movement_potential": "high" if len(reachable) > 5 else "medium" if len(reachable) > 2 else "low",
        }

    def _simulate_ransomware(self, asset_id: str) -> Dict[str, Any]:
        asset = self.assets[asset_id]
        neighbors = self._get_neighbors(asset_id, depth=2)
        file_servers = [n for n in neighbors if self.assets.get(n, TwinAsset("", "", {})).asset_type == "file_server"]
        db_servers = [n for n in neighbors if self.assets.get(n, TwinAsset("", "", {})).asset_type == "database"]
        domain_controllers = [n for n in neighbors if self.assets.get(n, TwinAsset("", "", {})).asset_type == "domain_controller"]

        encryption_scope = len(neighbors)
        backup_status = "likely_impacted" if domain_controllers else "potentially_available"

        return {
            "success": True,
            "scenario": "ransomware",
            "target": asset.to_dict(),
            "encryption_scope": encryption_scope,
            "file_servers_affected": len(file_servers),
            "databases_affected": len(db_servers),
            "domain_controllers_affected": len(domain_controllers),
            "backup_status": backup_status,
            "estimated_cost": self._estimate_ransomware_cost(asset, encryption_scope),
        }

    def _simulate_data_breach(self, asset_id: str) -> Dict[str, Any]:
        asset = self.assets[asset_id]
        neighbors = self._get_neighbors(asset_id, depth=3)

        sensitive_data_locations = []
        for nid in neighbors:
            na = self.assets.get(nid)
            if na and na.properties.get("has_sensitive_data"):
                sensitive_data_locations.append(nid)

        exposure_count = len(sensitive_data_locations)
        data_types = set()
        for sid in sensitive_data_locations:
            sa = self.assets.get(sid)
            if sa:
                dtypes = sa.properties.get("data_types", [])
                if isinstance(dtypes, list):
                    data_types.update(dtypes)

        return {
            "success": True,
            "scenario": "data_breach",
            "target": asset.to_dict(),
            "sensitive_data_locations": sensitive_data_locations,
            "data_types_exposed": list(data_types),
            "records_estimated": exposure_count * 10000,
            "gdpr_relevant": "pii" in {d.lower() for d in data_types},
            "hipaa_relevant": "phi" in {d.lower() for d in data_types},
            "estimated_breach_cost": self._estimate_breach_cost(exposure_count, data_types),
        }

    def _simulate_lateral_movement(self, asset_id: str, capability: str) -> Dict[str, Any]:
        asset = self.assets[asset_id]
        paths = self._find_all_paths(asset_id, None, depth=4)
        all_reachable = set()
        for p in paths:
            all_reachable.update(p[1:])

        hop_distribution = defaultdict(int)
        for nid in all_reachable:
            dist = len(self._find_path(asset_id, nid)) - 1 if self._find_path(asset_id, nid) else 99
            hop_distribution[f"{dist}_hop"] += 1

        return {
            "success": True,
            "scenario": "lateral_movement",
            "starting_asset": asset.to_dict(),
            "total_reachable_assets": len(all_reachable),
            "reachable_assets": list(all_reachable)[:20],
            "hop_distribution": dict(hop_distribution),
            "lateral_movement_velocity": "fast" if capability in {"high", "medium"} else "slow",
        }

    def _simulate_privilege_escalation(self, asset_id: str) -> Dict[str, Any]:
        asset = self.assets[asset_id]

        escalation_paths = []
        for nid in self.graph_adjacency.get(asset_id, {}):
            for rel_type in self.graph_adjacency[asset_id][nid]:
                if "admin" in rel_type.lower() or "privilege" in rel_type.lower():
                    escalation_paths.append({
                        "target": nid,
                        "relationship": rel_type,
                        "target_criticality": self.assets.get(nid, TwinAsset("", "", {})).criticality,
                    })

        return {
            "success": True,
            "scenario": "privilege_escalation",
            "starting_asset": asset.to_dict(),
            "privilege_escalation_paths": escalation_paths,
            "potential_admin_access": len(escalation_paths),
            "domain_admin_reachable": any("domain" in str(p).lower() for p in escalation_paths),
        }

    def _simulate_compromise_consequences(self, asset_id: str, question: str) -> Dict[str, Any]:
        asset = self.assets.get(asset_id)
        if not asset:
            return {"success": False, "error": "Asset not found"}

        immediate = self._simulate_compromise(asset_id, "medium")
        lateral = self._simulate_lateral_movement(asset_id, "medium")
        breach = self._simulate_data_breach(asset_id)

        return {
            "success": True,
            "question": question,
            "target_asset": asset.to_dict(),
            "compromise_analysis": immediate,
            "lateral_movement_analysis": lateral,
            "data_breach_analysis": breach,
            "blast_radius": len(self._get_neighbors(asset_id, depth=3)),
            "recommendations": self._generate_mitigation_recommendations(asset),
        }

    def _test_defense_controls(self, controls: List[str]) -> Dict[str, Any]:
        results = {}
        for control in controls:
            effectiveness = 0.0
            if control in {"mfa", "firewall", "edr", "dlp", "backup"}:
                effectiveness = 0.8
            elif control in {"ids", "siem", "iam", "pam"}:
                effectiveness = 0.6
            else:
                effectiveness = 0.3
            results[control] = {
                "control": control,
                "effectiveness": effectiveness,
                "breach_reduction": round(effectiveness * 100, 1),
                "recommendation": "Enhance" if effectiveness < 0.5 else "Maintain",
            }
        return {
            "success": True,
            "simulation_type": "blue_team_defense_test",
            "controls_tested": len(controls),
            "results": results,
        }

    def _test_detection_capabilities(self, controls: List[str]) -> Dict[str, Any]:
        detection_coverage = {}
        for technique_id in ["T1566", "T1059", "T1003", "T1021", "T1486"]:
            technique = self._get_technique_info(technique_id)
            detected = technique.get("name", "") if technique in controls else None
            detection_coverage[technique_id] = {
                "technique": technique.get("name", "Unknown"),
                "detectable": detected is not None,
                "mean_time_to_detect_minutes": 60 if detected else 9999,
            }
        return {
            "success": True,
            "simulation_type": "blue_team_detection_test",
            "coverage": detection_coverage,
        }

    def _get_technique_info(self, technique_id: str) -> Dict[str, Any]:
        from app.agents.mitre_mapper import mitre_mapper
        return mitre_mapper.get_technique(technique_id) or {}

    def _find_initial_access_points(self) -> List[str]:
        access_points = []
        for aid, asset in self.assets.items():
            if asset.asset_type in {"web_server", "vpn", "email_gateway", "remote_access"}:
                access_points.append(aid)
        return access_points[:10]

    def _find_paths_to_objective(self, start: str, objective: str) -> List[List[str]]:
        if objective == "domain_admin":
            targets = [aid for aid, a in self.assets.items()
                       if a.asset_type == "domain_controller" and a.criticality >= 4]
        elif objective == "data_exfiltration":
            targets = [aid for aid, a in self.assets.items()
                       if a.properties.get("has_sensitive_data")]
        elif objective == "impact":
            targets = [aid for aid, a in self.assets.items() if a.criticality >= 4]
        else:
            targets = [aid for aid in self.assets if aid != start]

        all_paths = []
        for target in targets[:20]:
            paths = self._find_all_paths(start, target, depth=4)
            all_paths.extend(paths[:2])

        all_paths.sort(key=lambda p: len(p))
        return all_paths[:5]

    def _add_relationship_internal(self, source: str, target: str, rel_type: str, properties: Dict):
        if source not in self.assets:
            return
        if target not in self.assets:
            return
        if target not in self.graph_adjacency[source]:
            self.graph_adjacency[source][target] = []
        if rel_type not in self.graph_adjacency[source][target]:
            self.graph_adjacency[source][target].append(rel_type)

        if source not in self.graph_adjacency[target]:
            self.graph_adjacency[target][source] = []
        reverse_type = self._reverse_relationship(rel_type)
        if reverse_type not in self.graph_adjacency[target][source]:
            self.graph_adjacency[target][source].append(reverse_type)

    def _add_relationship(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        source = input_data.get("source")
        target = input_data.get("target")
        rel_type = input_data.get("type", "connected_to")
        properties = input_data.get("properties", {})
        if source and target:
            self._add_relationship_internal(source, target, rel_type, properties)
            return {"success": True}
        return {"success": False, "error": "source and target required"}

    def _reverse_relationship(self, rel_type: str) -> str:
        reverse_map = {
            "connects_to": "connected_by",
            "depends_on": "depended_by",
            "contains": "contained_in",
            "manages": "managed_by",
            "has_access": "accessible_by",
            "parent_of": "child_of",
            "runs_on": "hosts",
        }
        return reverse_map.get(rel_type, f"reverse_{rel_type}")

    def _get_asset(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = input_data.get("asset_id")
        if asset_id and asset_id in self.assets:
            asset = self.assets[asset_id]
            connections = dict(self.graph_adjacency.get(asset_id, {}))
            return {"success": True, "asset": asset.to_dict(), "relationships": connections}
        return {"success": False, "error": "Asset not found"}

    def _list_assets(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        result = list(self.assets.values())
        if "asset_type" in filters:
            result = [a for a in result if a.asset_type == filters["asset_type"]]
        if "criticality_min" in filters:
            result = [a for a in result if a.criticality >= filters["criticality_min"]]
        return {
            "success": True,
            "total": len(result),
            "assets": [a.to_dict() for a in result],
        }

    def _find_path(self, source: str, target: str) -> List[str]:
        if source not in self.assets or target not in self.assets:
            return []
        if source == target:
            return [source]

        visited = {source}
        queue = deque([(source, [source])])

        while queue:
            current, path = queue.popleft()
            for neighbor in self.graph_adjacency.get(current, {}):
                if neighbor == target:
                    return path + [neighbor]
                if neighbor not in visited and neighbor in self.assets:
                    visited.add(neighbor)
                    queue.append((neighbor, path + [neighbor]))

        return []

    def _find_all_paths(self, source: str, target: Optional[str], max_depth: int = 5) -> List[List[str]]:
        if source not in self.assets:
            return []

        paths = []
        queue = deque([(source, [source])])

        while queue:
            current, path = queue.popleft()
            if len(path) > max_depth:
                continue
            for neighbor in self.graph_adjacency.get(current, {}):
                if neighbor in path:
                    continue
                if neighbor not in self.assets:
                    continue
                new_path = path + [neighbor]
                if target is None or neighbor == target:
                    paths.append(new_path)
                    if target is not None:
                        continue
                if len(new_path) <= max_depth:
                    queue.append((neighbor, new_path))

        if target:
            paths.sort(key=len)
        return paths[:20]

    def _get_neighbors(self, asset_id: str, depth: int = 1) -> List[str]:
        visited = {asset_id}
        queue = deque([(asset_id, 0)])
        neighbors = []

        while queue:
            current, d = queue.popleft()
            if d >= depth:
                continue
            for neighbor in self.graph_adjacency.get(current, {}):
                if neighbor not in visited and neighbor in self.assets:
                    visited.add(neighbor)
                    neighbors.append(neighbor)
                    queue.append((neighbor, d + 1))

        return neighbors

    def _calculate_exposure(self, asset_id: str) -> Dict[str, Any]:
        if asset_id not in self.assets:
            return {"error": "asset not found"}

        direct_connections = len(self.graph_adjacency.get(asset_id, {}))
        indirect_reachable = len(self._get_neighbors(asset_id, depth=3))
        critical_reachable = sum(1 for n in self._get_neighbors(asset_id, depth=3)
                                 if self.assets.get(n, TwinAsset("", "", {})).criticality >= 4)

        return {
            "asset_id": asset_id,
            "direct_connections": direct_connections,
            "indirect_reachable_assets": indirect_reachable,
            "critical_assets_reachable": critical_reachable,
            "exposure_score": round((direct_connections * 0.3 + indirect_reachable * 0.2 + critical_reachable * 0.5) / 10, 4),
        }

    def _score_attack_path(self, path: List[str]) -> float:
        score = 0.0
        for i in range(len(path) - 1):
            source = path[i]
            target = path[i + 1]
            source_asset = self.assets.get(source)
            target_asset = self.assets.get(target)
            if source_asset:
                score += source_asset.criticality * 0.1
            if target_asset:
                score += target_asset.criticality * 0.2
                if target_asset.properties.get("has_sensitive_data"):
                    score += 0.3
                if target_asset.asset_type == "domain_controller":
                    score += 0.4

            rel_types = self.graph_adjacency.get(source, {}).get(target, [])
            for rt in rel_types:
                if "admin" in rt.lower():
                    score += 0.3
                if "remote" in rt.lower():
                    score += 0.2

        return round(min(score, 1.0), 4)

    def _estimate_ransomware_cost(self, asset: TwinAsset, scope: int) -> Dict[str, Any]:
        base_cost = asset.criticality * 50000
        scope_cost = scope * 25000
        return {
            "estimated_total": base_cost + scope_cost,
            "ransom_amount": base_cost // 2,
            "downtime_cost_per_hour": asset.criticality * 10000,
            "remediation_cost": scope_cost,
        }

    def _estimate_breach_cost(self, exposure_count: int, data_types: Set[str]) -> Dict[str, Any]:
        per_record_cost = 150 if "pii" in {d.lower() for d in data_types} else 100
        total_records = exposure_count * 10000
        return {
            "estimated_total": total_records * per_record_cost,
            "per_record_cost": per_record_cost,
            "records_exposed": total_records,
            "gdpr_fine_risk": "high" if "pii" in {d.lower() for d in data_types} else "low",
            "notification_cost": exposure_count * 5000,
        }

    def _generate_mitigation_recommendations(self, asset: TwinAsset) -> List[str]:
        recommendations = []
        if asset.criticality >= 4:
            recommendations.append("Implement network segmentation around this critical asset")
            recommendations.append("Enable multi-factor authentication for all administrative access")
        if asset.asset_type in {"web_server", "vpn"}:
            recommendations.append("Ensure web application firewall is properly configured")
            recommendations.append("Regular penetration testing of external-facing services")
        neighbors = self._get_neighbors(asset.asset_id, depth=1)
        if len(neighbors) > 5:
            recommendations.append("Reduce lateral movement paths - implement least-privilege network access")
        return recommendations[:5]

    def _extract_asset_from_question(self, question: str) -> Optional[str]:
        words = question.lower().split()
        for aid in self.assets:
            if aid.lower() in words or aid.lower().replace("_", " ") in question.lower():
                return aid
        return None
