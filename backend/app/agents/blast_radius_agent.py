from typing import Dict, Any, Optional, List, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
from app.agents.base_agent import BaseAgent
from app.agents.digital_twin_agent import DigitalTwinAgent, TwinAsset
from app.core.logger import logger
from app.core.database import neo4j_driver


class BlastRadiusAgent(BaseAgent):
    def __init__(self, version: str = "1.0.0"):
        super().__init__(
            name="blast_radius_agent",
            agent_type="blast_radius",
            version=version,
        )
        self.digital_twin = DigitalTwinAgent()

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        self.last_run = datetime.utcnow()
        action = input_data.get("action", "calculate")

        try:
            if action == "calculate":
                return await self._calculate_blast_radius(input_data)
            elif action == "compromise_impact":
                return await self._compromise_impact(input_data)
            elif action == "asset_exposure":
                return await self._asset_exposure(input_data)
            elif action == "cascading_failure":
                return await self._cascading_failure(input_data)
            elif action == "department_impact":
                return await self._department_impact(input_data)
            elif action == "summary":
                return await self._summary(input_data)
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        except Exception as e:
            logger.error(f"BlastRadiusAgent error", error=str(e))
            self.update_metrics(False)
            return {"success": False, "error": str(e)}

    async def _calculate_blast_radius(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        compromised_asset = input_data.get("compromised_asset")
        include_indirect = input_data.get("include_indirect", True)
        max_depth = input_data.get("max_depth", 4)
        threat_context = input_data.get("threat_context", {})

        if not compromised_asset:
            return {"success": False, "error": "compromised_asset required"}

        await self.digital_twin.process({"action": "sync_from_graph"})

        if compromised_asset not in self.digital_twin.assets:
            return {"success": False, "error": f"Asset '{compromised_asset}' not found in digital twin"}

        direct_impact = self._get_direct_impact_zone(compromised_asset)
        indirect_impact = self._get_indirect_impact_zone(compromised_asset, max_depth) if include_indirect else []

        all_affected = list(set(direct_impact + indirect_impact))
        asset_details = self._get_asset_details(all_affected)
        criticality_breakdown = self._criticality_breakdown(all_affected)

        data_exposure = self._assess_data_exposure(all_affected)
        cost_estimate = self._estimate_blast_radius_cost(all_affected, data_exposure)
        department_impact = self._assess_department_impact(all_affected)
        service_impact = self._assess_service_impact(all_affected)

        contaminated_assets = self._get_contaminated_assets(compromised_asset, threat_context)

        result = {
            "success": True,
            "compromised_asset": compromised_asset,
            "blast_radius_summary": {
                "directly_affected": len(direct_impact),
                "indirectly_affected": len(indirect_impact),
                "total_affected": len(all_affected),
                "contaminated_count": len(contaminated_assets),
            },
            "criticality_breakdown": criticality_breakdown,
            "affected_assets": asset_details,
            "contaminated_assets": contaminated_assets,
            "data_exposure": data_exposure,
            "cost_impact": cost_estimate,
            "department_impact": department_impact,
            "service_impact": service_impact,
            "lateral_movement_potential": self._assess_lateral_movement_potential(compromised_asset),
            "mitigation_priorities": self._prioritize_mitigations(compromised_asset, all_affected),
            "timestamp": datetime.utcnow().isoformat(),
        }

        if criticality_breakdown.get("critical", 0) > 0:
            await self.publish_event("blast_radius.critical_assets_affected", {
                "compromised_asset": compromised_asset,
                "critical_assets_affected": criticality_breakdown.get("critical", 0),
            })

        return result

    async def _compromise_impact(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = input_data.get("asset_id")
        if not asset_id:
            return {"success": False, "error": "asset_id required"}

        return await self._calculate_blast_radius({
            "compromised_asset": asset_id,
            "max_depth": input_data.get("max_depth", 3),
        })

    async def _asset_exposure(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = input_data.get("asset_id")
        if not asset_id or asset_id not in self.digital_twin.assets:
            await self.digital_twin.process({"action": "sync_from_graph"})

        if not asset_id or asset_id not in self.digital_twin.assets:
            return {"success": False, "error": "Asset not found"}

        exposure = self.digital_twin._calculate_exposure(asset_id)
        return {"success": True, "asset_exposure": exposure}

    async def _cascading_failure(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = input_data.get("asset_id")
        if not asset_id:
            return {"success": False, "error": "asset_id required"}

        await self.digital_twin.process({"action": "sync_from_graph"})
        if asset_id not in self.digital_twin.assets:
            return {"success": False, "error": "Asset not found"}

        cascading = self._simulate_cascading_failure(asset_id)
        return {"success": True, "cascading_failure": cascading}

    async def _department_impact(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = input_data.get("asset_id")
        if not asset_id:
            return {"success": False, "error": "asset_id required"}

        await self.digital_twin.process({"action": "sync_from_graph"})
        all_affected = self._get_direct_impact_zone(asset_id) + self._get_indirect_impact_zone(asset_id, 3)
        department_impact = self._assess_department_impact(list(set(all_affected)))

        return {"success": True, "department_impact": department_impact}

    async def _summary(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        asset_id = input_data.get("asset_id")
        if not asset_id:
            return {"success": False, "error": "asset_id required"}

        result = await self._calculate_blast_radius({
            "compromised_asset": asset_id,
            "max_depth": input_data.get("max_depth", 3),
        })

        if not result.get("success"):
            return result

        summary = {
            "asset": asset_id,
            "risk_score": self._calculate_risk_score(result),
            "total_assets_affected": result["blast_radius_summary"]["total_affected"],
            "critical_assets_affected": result["criticality_breakdown"].get("critical", 0),
            "estimated_cost": result["cost_impact"].get("estimated_total", 0),
            "departments_affected": len(result["department_impact"]),
            "data_types_exposed": result["data_exposure"].get("data_categories", []),
            "lateral_movement_risk": result["lateral_movement_potential"],
            "top_recommendation": result["mitigation_priorities"][0] if result["mitigation_priorities"] else None,
        }

        return {"success": True, "summary": summary}

    def _get_direct_impact_zone(self, asset_id: str) -> List[str]:
        impacted = []
        for neighbor in self.digital_twin.graph_adjacency.get(asset_id, {}):
            impacted.append(neighbor)
        return impacted

    def _get_indirect_impact_zone(self, asset_id: str, max_depth: int) -> List[str]:
        visited = {asset_id}
        queue = deque([(asset_id, 0)])
        indirect = []

        while queue:
            current, depth = queue.popleft()
            if depth >= max_depth:
                continue
            for neighbor in self.digital_twin.graph_adjacency.get(current, {}):
                if neighbor not in visited and neighbor in self.digital_twin.assets:
                    visited.add(neighbor)
                    if depth + 1 > 1:
                        indirect.append(neighbor)
                    queue.append((neighbor, depth + 1))

        return indirect

    def _get_asset_details(self, asset_ids: List[str]) -> List[Dict[str, Any]]:
        details = []
        for aid in asset_ids:
            asset = self.digital_twin.assets.get(aid)
            if asset:
                details.append({
                    "asset_id": aid,
                    "asset_type": asset.asset_type,
                    "criticality": asset.criticality,
                    "properties": {k: v for k, v in asset.properties.items() if k != "password"},
                })
        return details

    def _criticality_breakdown(self, asset_ids: List[str]) -> Dict[str, int]:
        breakdown = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for aid in asset_ids:
            asset = self.digital_twin.assets.get(aid)
            if asset:
                if asset.criticality >= 5:
                    breakdown["critical"] += 1
                elif asset.criticality >= 4:
                    breakdown["high"] += 1
                elif asset.criticality >= 2:
                    breakdown["medium"] += 1
                else:
                    breakdown["low"] += 1
        return breakdown

    def _assess_data_exposure(self, asset_ids: List[str]) -> Dict[str, Any]:
        data_categories = set()
        sensitive_count = 0

        for aid in asset_ids:
            asset = self.digital_twin.assets.get(aid)
            if asset:
                if asset.properties.get("has_sensitive_data"):
                    sensitive_count += 1
                    dtypes = asset.properties.get("data_types", [])
                    if isinstance(dtypes, list):
                        data_categories.update(dtypes)

        return {
            "has_sensitive_data": sensitive_count > 0,
            "sensitive_asset_count": sensitive_count,
            "data_categories": list(data_categories),
            "exposure_risk": "critical" if sensitive_count > 2 else "high" if sensitive_count > 0 else "medium",
        }

    def _estimate_blast_radius_cost(self, asset_ids: List[str], data_exposure: Dict) -> Dict[str, Any]:
        total_cost = 0
        breakdown = {}

        for aid in asset_ids:
            asset = self.digital_twin.assets.get(aid)
            if asset:
                base_cost = asset.criticality * 25000
                total_cost += base_cost
                asset_type = asset.asset_type
                if asset_type not in breakdown:
                    breakdown[asset_type] = 0
                breakdown[asset_type] += base_cost

        if data_exposure.get("has_sensitive_data"):
            breach_cost = data_exposure.get("sensitive_asset_count", 0) * 150000
            total_cost += breach_cost
            breakdown["data_breach_penalties"] = breach_cost

        downtime_hours = len(asset_ids) * 4
        downtime_cost = downtime_hours * 10000
        total_cost += downtime_cost
        breakdown["downtime"] = downtime_cost

        return {
            "estimated_total": total_cost,
            "breakdown": breakdown,
            "downtime_hours": downtime_hours,
            "currency": "USD",
        }

    def _assess_department_impact(self, asset_ids: List[str]) -> Dict[str, Any]:
        department_map = defaultdict(list)
        for aid in asset_ids:
            asset = self.digital_twin.assets.get(aid)
            if asset:
                dept = asset.properties.get("department", asset.properties.get("owner", "unknown"))
                department_map[str(dept)].append(aid)

        departments = {}
        for dept, assets in department_map.items():
            critical_assets = sum(1 for a in assets if self.digital_twin.assets.get(a, TwinAsset("", "", {})).criticality >= 4)
            departments[dept] = {
                "assets_affected": len(assets),
                "critical_assets_affected": critical_assets,
                "impact_severity": "critical" if critical_assets > 0 else "high" if len(assets) > 3 else "medium",
            }

        return departments

    def _assess_service_impact(self, asset_ids: List[str]) -> Dict[str, Any]:
        service_map = defaultdict(list)
        for aid in asset_ids:
            asset = self.digital_twin.assets.get(aid)
            if asset:
                services = asset.properties.get("services", [])
                if isinstance(services, list):
                    for svc in services:
                        service_map[str(svc)].append(aid)
                if not services:
                    service_map["unknown"].append(aid)

        impacted_services = {}
        for svc, assets in service_map.items():
            impacted_services[svc] = {
                "assets_affected": len(assets),
                "status": "degraded" if len(assets) > 2 else "at_risk",
            }

        return {
            "services_impacted": len(impacted_services),
            "service_details": impacted_services,
        }

    def _get_contaminated_assets(self, asset_id: str, threat_context: Dict[str, Any]) -> List[Dict[str, Any]]:
        contaminated = []
        technique = threat_context.get("technique_id", "")

        if technique in {"T1021", "T1550"}:
            for neighbor in self.digital_twin.graph_adjacency.get(asset_id, {}):
                asset = self.digital_twin.assets.get(neighbor)
                if asset:
                    contaminated.append({
                        "asset_id": neighbor,
                        "reason": "lateral_movement_target",
                        "confidence": 0.75,
                    })

        if "credential" in str(threat_context).lower():
            for aid, asset in self.digital_twin.assets.items():
                if asset.asset_type == "domain_controller":
                    contaminated.append({
                        "asset_id": aid,
                        "reason": "credential_theft_target",
                        "confidence": 0.85,
                    })

        return contaminated[:20]

    def _assess_lateral_movement_potential(self, asset_id: str) -> str:
        connections = len(self.digital_twin.graph_adjacency.get(asset_id, {}))
        if connections >= 10:
            return "critical"
        elif connections >= 5:
            return "high"
        elif connections >= 2:
            return "medium"
        return "low"

    def _prioritize_mitigations(self, compromised: str, affected: List[str]) -> List[str]:
        priorities = []

        for aid in affected:
            asset = self.digital_twin.assets.get(aid)
            if asset and asset.criticality >= 5:
                priorities.append(f"CRITICAL: Isolate {aid} - critical infrastructure asset")

        if self.digital_twin.graph_adjacency.get(compromised, {}):
            priorities.append(f"Immediately isolate {compromised} and segment network access")
            priorities.append(f"Block all lateral movement paths from {compromised}")

        for aid in affected:
            asset = self.digital_twin.assets.get(aid)
            if asset and asset.properties.get("has_sensitive_data"):
                priorities.append(f"Protect {aid} - contains sensitive data, enable DLP")

        priorities.append("Enable enhanced logging and monitoring on all affected assets")
        priorities.append("Notify SOC and initiate incident response procedures")

        return priorities[:8]

    def _simulate_cascading_failure(self, asset_id: str) -> Dict[str, Any]:
        failure_graph = defaultdict(list)
        visited = {asset_id}
        queue = deque([(asset_id, 0)])
        cascade_levels = defaultdict(list)

        while queue:
            current, level = queue.popleft()
            cascade_levels[level].append(current)

            for neighbor in self.digital_twin.graph_adjacency.get(current, {}):
                if neighbor not in visited and neighbor in self.digital_twin.assets:
                    visited.add(neighbor)
                    failure_graph[current].append(neighbor)
                    queue.append((neighbor, level + 1))

        total_affected = len(visited) - 1
        return {
            "root_cause": asset_id,
            "cascade_levels": dict(cascade_levels),
            "total_failed": total_affected,
            "cascade_depth": max(cascade_levels.keys()) if cascade_levels else 0,
            "failure_chain": [{"from": k, "to": v} for k, v in failure_graph.items()],
        }

    def _calculate_risk_score(self, blast_result: Dict[str, Any]) -> float:
        score = 0.0
        total_affected = blast_result.get("blast_radius_summary", {}).get("total_affected", 0)
        score += min(total_affected * 0.05, 0.2)

        critical_count = blast_result.get("criticality_breakdown", {}).get("critical", 0)
        score += min(critical_count * 0.15, 0.3)

        if blast_result.get("data_exposure", {}).get("has_sensitive_data"):
            score += 0.2

        lateral = blast_result.get("lateral_movement_potential", "low")
        if lateral == "critical":
            score += 0.2
        elif lateral == "high":
            score += 0.15

        department_count = len(blast_result.get("department_impact", {}))
        score += min(department_count * 0.05, 0.1)

        return round(min(score, 1.0), 4)
