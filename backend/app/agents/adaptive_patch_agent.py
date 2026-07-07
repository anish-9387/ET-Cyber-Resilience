from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from app.agents.base_agent import BaseAgent
from app.agents.mitre_mapper import mitre_mapper
from app.core.logger import logger
import json, hashlib


class AdaptivePatchAgent(BaseAgent):
    def __init__(self, version: str = "1.0.0"):
        super().__init__(
            name="adaptive_patch_agent",
            agent_type="adaptive_patch",
            version=version,
        )
        self.vulnerability_data: Dict[str, Dict[str, Any]] = {}
        self.asset_criticality_cache: Dict[str, int] = {}
        self.threat_intel_cache: Dict[str, List[str]] = defaultdict(list)

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        self.last_run = datetime.utcnow()
        action = input_data.get("action", "prioritize")

        try:
            if action == "prioritize":
                return await self._prioritize(input_data)
            elif action == "calculate_risk":
                return await self._calculate_risk(input_data)
            elif action == "add_vulnerability":
                return await self._add_vulnerability(input_data)
            elif action == "batch_ingest":
                return await self._batch_ingest(input_data)
            elif action == "get_patch_list":
                return self._get_patch_list(input_data)
            elif action == "update_threat_intel":
                return self._update_threat_intel(input_data)
            elif action == "get_remediation_plan":
                return await self._get_remediation_plan(input_data)
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        except Exception as e:
            logger.error(f"AdaptivePatchAgent error", error=str(e))
            self.update_metrics(False)
            return {"success": False, "error": str(e)}

    async def _prioritize(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        vulnerabilities = input_data.get("vulnerabilities", [])
        environment = input_data.get("environment", {})

        if not vulnerabilities:
            vulns_from_store = list(self.vulnerability_data.values())
            if not vulns_from_store:
                return {"success": False, "error": "No vulnerabilities to prioritize"}
            vulnerabilities = vulns_from_store

        scored_vulns = []
        for vuln in vulnerabilities:
            risk_score, risk_factors = self._calculate_business_risk(vuln, environment)
            vuln["business_risk_score"] = risk_score
            vuln["risk_factors"] = risk_factors
            scored_vulns.append(vuln)

        scored_vulns.sort(key=lambda x: -x.get("business_risk_score", 0))

        for vuln in scored_vulns:
            vuln_id = vuln.get("id", vuln.get("cve", vuln.get("vulnerability_id", "unknown")))
            if vuln_id:
                self.vulnerability_data[vuln_id] = vuln

        priority_tiers = self._assign_priority_tiers(scored_vulns)
        patch_windows = self._recommend_patch_windows(scored_vulns, environment)
        critical_count = sum(1 for v in scored_vulns if v.get("business_risk_score", 0) >= 8)

        result = {
            "success": True,
            "total_analyzed": len(scored_vulns),
            "critical_count": critical_count,
            "high_count": sum(1 for v in scored_vulns if 6 <= v.get("business_risk_score", 0) < 8),
            "medium_count": sum(1 for v in scored_vulns if 4 <= v.get("business_risk_score", 0) < 6),
            "low_count": sum(1 for v in scored_vulns if v.get("business_risk_score", 0) < 4),
            "priority_tiers": priority_tiers,
            "patch_windows": patch_windows,
            "prioritized_vulnerabilities": scored_vulns[:50],
            "timestamp": datetime.utcnow().isoformat(),
        }

        if critical_count > 0:
            await self.publish_event("patch.critical_vulnerabilities", {
                "count": critical_count,
                "top_vulnerabilities": [v.get("cve", v.get("id", "unknown")) for v in scored_vulns[:5]],
            })

        return result

    async def _calculate_risk(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        vulnerability = input_data.get("vulnerability", input_data)
        environment = input_data.get("environment", {})
        risk_score, risk_factors = self._calculate_business_risk(vulnerability, environment)

        return {
            "success": True,
            "business_risk_score": risk_score,
            "risk_factors": risk_factors,
            "cvss_score": vulnerability.get("cvss_score", vulnerability.get("cvss", 0)),
            "risk_delta": round(risk_score - float(vulnerability.get("cvss_score", vulnerability.get("cvss", 0))), 2),
        }

    async def _add_vulnerability(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        vuln = input_data.get("vulnerability", input_data)
        vuln_id = vuln.get("id", vuln.get("cve", vuln.get("vulnerability_id")))
        if not vuln_id:
            vuln_id = hashlib.md5(json.dumps(vuln, default=str).encode()).hexdigest()[:12]
            vuln["id"] = vuln_id
        self.vulnerability_data[vuln_id] = vuln
        return {"success": True, "vulnerability_id": vuln_id}

    async def _batch_ingest(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        vulnerabilities = input_data.get("vulnerabilities", [])
        if not vulnerabilities:
            return {"success": False, "error": "No vulnerabilities provided"}

        count = 0
        for vuln in vulnerabilities:
            vuln_id = vuln.get("id", vuln.get("cve"))
            if vuln_id:
                self.vulnerability_data[vuln_id] = vuln
                count += 1

        return await self._prioritize({"vulnerabilities": list(self.vulnerability_data.values())})

    def _get_patch_list(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        min_risk = input_data.get("min_risk_score", 0)
        limit = input_data.get("limit", 100)

        filtered = [v for v in self.vulnerability_data.values()
                    if v.get("business_risk_score", v.get("cvss_score", 0)) >= min_risk]
        filtered.sort(key=lambda x: -x.get("business_risk_score", x.get("cvss_score", 0)))

        return {
            "success": True,
            "total": len(filtered),
            "patches": filtered[:limit],
        }

    async def _update_threat_intel(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        threat_intel = input_data.get("threat_intel", {})
        cve = threat_intel.get("cve")
        exploited_in_wild = threat_intel.get("exploited_in_wild", False)
        apt_targeting = threat_intel.get("apt_targeting", False)
        ransomware_association = threat_intel.get("ransomware_association", False)

        if cve:
            self.threat_intel_cache[cve].extend([
                "exploited_in_wild" if exploited_in_wild else "",
                "apt_targeting" if apt_targeting else "",
                "ransomware_association" if ransomware_association else "",
            ])
            self.threat_intel_cache[cve] = list(filter(None, set(self.threat_intel_cache[cve])))

        return {
            "success": True,
            "cve": cve,
            "threat_factors": self.threat_intel_cache.get(cve, []),
        }

    async def _get_remediation_plan(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        vulnerabilities = input_data.get("vulnerabilities", list(self.vulnerability_data.values()))
        environment = input_data.get("environment", {})

        if not vulnerabilities:
            return {"success": False, "error": "No vulnerabilities"}

        scored = []
        for vuln in vulnerabilities:
            score, factors = self._calculate_business_risk(vuln, environment)
            scored.append((vuln, score, factors))

        scored.sort(key=lambda x: -x[1])

        plan = []
        for vuln, score, factors in scored[:20]:
            cve = vuln.get("cve", vuln.get("id", "unknown"))
            plan.append({
                "cve": cve,
                "package": vuln.get("package", vuln.get("software", "unknown")),
                "business_risk_score": score,
                "priority": "immediate" if score >= 8 else "24_hours" if score >= 6 else "7_days" if score >= 4 else "next_cycle",
                "remediation": f"Update {vuln.get('package', vuln.get('software', 'unknown'))} to patched version",
                "risk_factors": factors,
                "affected_assets": vuln.get("affected_assets", vuln.get("assets", [])),
            })

        return {
            "success": True,
            "plan": plan,
            "total_in_plan": len(plan),
        }

    def _calculate_business_risk(self, vuln: Dict[str, Any], environment: Dict[str, Any]) -> Tuple[float, List[str]]:
        risk_score = 0.0
        risk_factors = []

        cvss = float(vuln.get("cvss_score", vuln.get("cvss", vuln.get("severity_score", 0))))
        if cvss >= 9.0:
            risk_score += 3.0
            risk_factors.append(f"CVSS score {cvss} (Critical)")
        elif cvss >= 7.0:
            risk_score += 2.0
            risk_factors.append(f"CVSS score {cvss} (High)")
        elif cvss >= 4.0:
            risk_score += 1.0
            risk_factors.append(f"CVSS score {cvss} (Medium)")

        cve = vuln.get("cve", vuln.get("id", ""))
        if cve in self.threat_intel_cache:
            intel = self.threat_intel_cache[cve]
            if "exploited_in_wild" in intel:
                risk_score += 2.0
                risk_factors.append("Exploited in the wild")
            if "apt_targeting" in intel:
                risk_score += 1.5
                risk_factors.append("Actively targeted by APT groups")
            if "ransomware_association" in intel:
                risk_score += 1.5
                risk_factors.append("Associated with ransomware campaigns")
        else:
            epss = vuln.get("epss_score", vuln.get("exploit_probability", 0))
            if isinstance(epss, (int, float)) and epss > 0.5:
                risk_score += 1.0
                risk_factors.append(f"High exploit probability (EPSS: {epss})")

        internet_facing = vuln.get("internet_facing", vuln.get("exposed", False))
        if internet_facing or environment.get("internet_facing", False):
            risk_score += 1.5
            risk_factors.append("Internet-facing asset")

        asset_criticality = vuln.get("asset_criticality", vuln.get("criticality", 0))
        if isinstance(asset_criticality, str):
            criticality_map = {"critical": 5, "high": 4, "medium": 3, "low": 2}
            asset_criticality = criticality_map.get(asset_criticality.lower(), 3)

        if asset_criticality >= 4:
            risk_score += 1.5
            risk_factors.append(f"High criticality asset (level {asset_criticality})")
        elif asset_criticality >= 3:
            risk_score += 0.5

        near_domain_controller = vuln.get("near_domain_controller", vuln.get("near_dc", False))
        if near_domain_controller:
            risk_score += 1.0
            risk_factors.append("Near Domain Controller")

        blast_radius = vuln.get("blast_radius_score", vuln.get("blast_radius", 0))
        if isinstance(blast_radius, (int, float)) and blast_radius >= 4:
            risk_score += 1.0
            risk_factors.append("High blast radius potential")
        elif isinstance(blast_radius, str):
            if blast_radius.lower() in {"high", "critical"}:
                risk_score += 1.0
                risk_factors.append("High blast radius potential")

        public_exploit = vuln.get("public_exploit_available", vuln.get("public_exploit", False))
        if public_exploit:
            risk_score += 1.0
            risk_factors.append("Public exploit available")

        age_days = vuln.get("age_days", vuln.get("disclosure_age_days", 0))
        if age_days > 365:
            risk_score -= 0.5
            risk_factors.append("Vulnerability older than 1 year")
        elif age_days < 30:
            risk_score += 0.5
            risk_factors.append("Recently disclosed (< 30 days)")

        affected_assets = vuln.get("affected_assets", vuln.get("assets", []))
        if isinstance(affected_assets, list) and len(affected_assets) > 5:
            risk_score += 1.0
            risk_factors.append(f"Affects {len(affected_assets)} assets")

        attack_vector = vuln.get("attack_vector", "").lower()
        if attack_vector in {"network", "adjacent_network"}:
            risk_score += 0.5
            risk_factors.append(f"Network-adjacent attack vector")

        risk_score = max(0.0, min(risk_score, 10.0))

        return round(risk_score, 2), risk_factors

    def _assign_priority_tiers(self, vulnerabilities: List[Dict]) -> Dict[str, List[str]]:
        tiers = {"immediate": [], "24_hours": [], "7_days": [], "next_cycle": []}

        for vuln in vulnerabilities:
            vuln_id = vuln.get("cve", vuln.get("id", vuln.get("vulnerability_id", "unknown")))
            score = vuln.get("business_risk_score", vuln.get("cvss_score", 0))

            if score >= 8:
                tiers["immediate"].append(vuln_id)
            elif score >= 6:
                tiers["24_hours"].append(vuln_id)
            elif score >= 4:
                tiers["7_days"].append(vuln_id)
            else:
                tiers["next_cycle"].append(vuln_id)

        return tiers

    def _recommend_patch_windows(self, vulnerabilities: List[Dict], environment: Dict[str, Any]) -> Dict[str, Any]:
        critical = [v for v in vulnerabilities if v.get("business_risk_score", 0) >= 8]
        high = [v for v in vulnerabilities if 6 <= v.get("business_risk_score", 0) < 8]

        now = datetime.utcnow()
        return {
            "immediate_patch_window": {
                "count": len(critical),
                "recommended_time": "ASAP - out of band",
                "deadline": now.isoformat(),
            },
            "urgent_patch_window": {
                "count": len(high),
                "recommended_time": "Next available maintenance window",
                "deadline": (now + timedelta(hours=24)).isoformat(),
            },
            "standard_patch_window": {
                "count": len(vulnerabilities) - len(critical) - len(high),
                "recommended_time": "Next regular patch cycle",
                "deadline": (now + timedelta(days=7)).isoformat(),
            },
        }
