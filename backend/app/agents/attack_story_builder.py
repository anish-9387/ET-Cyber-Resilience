from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timedelta
from collections import defaultdict
from app.agents.base_agent import BaseAgent
from app.agents.mitre_mapper import mitre_mapper, TACTIC_ORDER
from app.agents.threat_correlation_agent import ThreatCorrelationAgent
from app.core.logger import logger
import hashlib, json


ATTACK_CHAINS = [
    {
        "name": "Ransomware Deployment",
        "steps": [
            "phishing", "execution", "persistence", "defense_evasion",
            "credential_access", "discovery", "lateral_movement",
            "collection", "exfiltration", "impact"
        ],
        "common_techniques": ["T1566", "T1204", "T1059", "T1547", "T1562",
                              "T1003", "T1087", "T1021", "T1486", "T1490"],
    },
    {
        "name": "APT Lateral Movement",
        "steps": [
            "initial_access", "execution", "privilege_escalation",
            "credential_access", "discovery", "lateral_movement",
            "persistence", "collection", "exfiltration"
        ],
        "common_techniques": ["T1190", "T1059", "T1068", "T1003", "T1087",
                              "T1021", "T1098", "T1005", "T1048"],
    },
    {
        "name": "Insider Data Theft",
        "steps": [
            "discovery", "collection", "exfiltration"
        ],
        "common_techniques": ["T1087", "T1005", "T1039", "T1048", "T1567"],
    },
    {
        "name": "Supply Chain Attack",
        "steps": [
            "initial_access", "execution", "persistence",
            "defense_evasion", "credential_access", "lateral_movement",
            "collection", "exfiltration"
        ],
        "common_techniques": ["T1195", "T1204", "T1546", "T1562", "T1003",
                              "T1021", "T1005", "T1048"],
    },
    {
        "name": "Web Application Attack",
        "steps": [
            "initial_access", "execution", "privilege_escalation",
            "persistence", "defense_evasion", "exfiltration"
        ],
        "common_techniques": ["T1190", "T1059", "T1068", "T1505", "T1562", "T1048"],
    },
    {
        "name": "OT/ICS Attack",
        "steps": [
            "initial_access", "execution", "persistence",
            "discovery", "lateral_movement", "impact"
        ],
        "common_techniques": ["T1190", "T1059", "T1547", "T1087", "T1021", "T1486"],
    },
]


class AttackStoryBuilder(BaseAgent):
    def __init__(self, version: str = "1.0.0"):
        super().__init__(
            name="attack_story_builder",
            agent_type="attack_story",
            version=version,
        )
        self.threat_correlator = ThreatCorrelationAgent()
        self.stories: Dict[str, Dict[str, Any]] = {}

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        self.last_run = datetime.utcnow()
        action = input_data.get("action", "build_story")

        try:
            if action == "ingest_alert":
                return await self._ingest_alert(input_data)
            elif action == "build_story":
                return await self._build_story(input_data)
            elif action == "get_story":
                return self._get_story(input_data)
            elif action == "get_all_stories":
                return self._get_all_stories()
            elif action == "update_story":
                return await self._update_story(input_data)
            elif action == "close_story":
                return await self._close_story(input_data)
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        except Exception as e:
            logger.error(f"AttackStoryBuilder error", error=str(e))
            self.update_metrics(False)
            return {"success": False, "error": str(e)}

    async def _ingest_alert(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        alert = input_data.get("alert", input_data)
        if "alert_id" not in alert:
            alert["alert_id"] = hashlib.md5(str(alert).encode()).hexdigest()[:12]
        if "timestamp" not in alert:
            alert["timestamp"] = datetime.utcnow().isoformat()

        mapped = mitre_mapper.map_event(alert)
        alert["mitre"] = mapped

        correlation = await self.threat_correlator.process({
            "action": "ingest_event",
            "event": alert,
        })

        if correlation.get("success"):
            await self.publish_event("alert.ingested", {
                "alert_id": alert["alert_id"],
                "mitre_tactic": mapped.get("tactic"),
                "technique_id": mapped.get("technique_id"),
            })

        return {
            "success": True,
            "alert_id": alert["alert_id"],
            "mitre_mapping": mapped,
        }

    async def _build_story(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        alerts = input_data.get("alerts", [])
        story_id = input_data.get("story_id")

        if not alerts and not story_id:
            return {"success": False, "error": "Provide alerts or existing story_id"}

        if story_id and story_id in self.stories:
            existing = self.stories[story_id]
            existing_alerts = existing.get("alerts", [])
            new_alerts = [a for a in alerts if a.get("alert_id") not in {ea.get("alert_id") for ea in existing_alerts}]
            existing_alerts.extend(new_alerts)
            alerts = existing_alerts
        else:
            story_id = story_id or hashlib.md5(str(alerts).encode()).hexdigest()[:16]

        if not alerts:
            return {"success": False, "error": "No alerts provided"}

        processed_alerts = []
        tactic_counts = defaultdict(int)
        technique_ids = set()
        unique_entities = set()
        timeline = []

        for alert in alerts:
            if "mitre" not in alert:
                alert["mitre"] = mitre_mapper.map_event(alert)

            processed_alerts.append(alert)
            tactic = alert["mitre"].get("tactic", "unknown")
            tactic_lower = tactic.lower().replace(" ", "_")
            tactic_counts[tactic_lower] += 1

            tid = alert["mitre"].get("technique_id")
            if tid:
                technique_ids.add(tid)

            for field in ["source", "target", "entity_id", "user", "host"]:
                val = alert.get(field)
                if val:
                    unique_entities.add(str(val))

            ts = alert.get("timestamp", alert.get("time", ""))
            if ts:
                timeline.append((ts, alert["mitre"].get("technique_name", "unknown"), alert.get("alert_id", "")))

        timeline.sort(key=lambda x: x[0])

        detected_chain = self._classify_attack_chain(tactic_counts, list(technique_ids))
        current_stage = self._determine_current_stage(tactic_counts, detected_chain)
        next_stage = self._predict_next_stage(current_stage, detected_chain)

        confidence = self._calculate_story_confidence(tactic_counts, technique_ids, len(alerts))

        story = {
            "story_id": story_id,
            "attack_chain": detected_chain["name"] if detected_chain else "Unknown Pattern",
            "confidence": round(confidence, 4),
            "current_stage": current_stage,
            "next_probable_stage": next_stage,
            "stage_progress": self._calculate_stage_progress(tactic_counts, detected_chain),
            "alerts_count": len(processed_alerts),
            "tactics_detected": dict(tactic_counts),
            "techniques_detected": list(technique_ids),
            "unique_entities": list(unique_entities),
            "timeline": timeline,
            "mitre_attack_version": "14.1",
            "severity": self._calculate_severity(detected_chain, len(processed_alerts), tactic_counts),
            "status": "active",
            "created_at": datetime.utcnow().isoformat(),
            "updated_at": datetime.utcnow().isoformat(),
        }

        self.stories[story_id] = story

        if story["severity"] >= 7:
            await self.publish_event("attack_story.critical", story)

        return {"success": True, "story": story}

    async def _update_story(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        story_id = input_data.get("story_id")
        if not story_id or story_id not in self.stories:
            return {"success": False, "error": "Story not found"}

        new_alerts = input_data.get("alerts", [])
        if new_alerts:
            return await self._build_story({
                "story_id": story_id,
                "alerts": new_alerts,
            })

        return {"success": False, "error": "No alerts to update"}

    async def _close_story(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        story_id = input_data.get("story_id")
        resolution = input_data.get("resolution", "investigated")
        if story_id and story_id in self.stories:
            self.stories[story_id]["status"] = "closed"
            self.stories[story_id]["resolution"] = resolution
            self.stories[story_id]["closed_at"] = datetime.utcnow().isoformat()
            return {"success": True, "story": self.stories[story_id]}
        return {"success": False, "error": "Story not found"}

    def _get_story(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        story_id = input_data.get("story_id")
        if story_id and story_id in self.stories:
            return {"success": True, "story": self.stories[story_id]}
        return {"success": False, "error": "Story not found"}

    def _get_all_stories(self) -> Dict[str, Any]:
        active = {sid: s for sid, s in self.stories.items() if s.get("status") == "active"}
        closed = {sid: s for sid, s in self.stories.items() if s.get("status") == "closed"}
        return {
            "success": True,
            "total": len(self.stories),
            "active": len(active),
            "closed": len(closed),
            "stories": list(self.stories.values()),
        }

    def _classify_attack_chain(self, tactic_counts: Dict[str, int], techniques: List[str]) -> Dict[str, Any]:
        best_match = None
        best_score = 0

        for chain in ATTACK_CHAINS:
            score = 0
            for step in chain["steps"]:
                if tactic_counts.get(step, 0) > 0:
                    score += 2

            for ct in chain["common_techniques"]:
                if ct in techniques:
                    score += 3

            total_steps = len(chain["steps"])
            if total_steps > 0:
                score = score / (total_steps * 2 + len(chain["common_techniques"]) * 3)

            if score > best_score:
                best_score = score
                best_match = chain

        if best_match and best_score >= 0.15:
            return best_match

        return ATTACK_CHAINS[0]

    def _determine_current_stage(self, tactic_counts: Dict[str, int], chain: Dict[str, Any]) -> str:
        if not chain:
            return "unknown"

        last_detected_idx = -1
        for i, step in enumerate(chain["steps"]):
            if tactic_counts.get(step, 0) > 0:
                last_detected_idx = i

        if last_detected_idx < 0:
            return "initial_reconnaissance"

        return chain["steps"][last_detected_idx]

    def _predict_next_stage(self, current_stage: str, chain: Dict[str, Any]) -> str:
        if not chain or not current_stage:
            return "unknown"

        try:
            current_idx = chain["steps"].index(current_stage)
            if current_idx < len(chain["steps"]) - 1:
                return chain["steps"][current_idx + 1]
            return "attack_completed"
        except ValueError:
            return "unknown"

    def _calculate_story_confidence(self, tactic_counts: Dict[str, int], techniques: List[str], alert_count: int) -> float:
        confidence = 0.0
        unique_tactics = len([v for v in tactic_counts.values() if v > 0])
        confidence += min(unique_tactics * 0.15, 0.45)
        confidence += min(len(techniques) * 0.08, 0.25)
        confidence += min(alert_count * 0.05, 0.2)
        return min(confidence, 1.0)

    def _calculate_stage_progress(self, tactic_counts: Dict[str, int], chain: Dict[str, Any]) -> float:
        if not chain:
            return 0.0
        detected = sum(1 for step in chain["steps"] if tactic_counts.get(step, 0) > 0)
        return round(detected / len(chain["steps"]), 4) if chain["steps"] else 0.0

    def _calculate_severity(self, chain: Dict[str, Any], alert_count: int, tactic_counts: Dict[str, int]) -> int:
        severity = 3
        if chain and chain["name"] == "Ransomware Deployment":
            severity += 3
        elif chain and chain["name"] == "APT Lateral Movement":
            severity += 3
        elif chain and chain["name"] == "OT/ICS Attack":
            severity += 4
        elif chain and chain["name"] == "Supply Chain Attack":
            severity += 2

        if tactic_counts.get("impact", 0) > 0:
            severity += 2
        if tactic_counts.get("exfiltration", 0) > 0:
            severity += 2
        if tactic_counts.get("lateral_movement", 0) > 0:
            severity += 2

        if alert_count >= 10:
            severity += 1
        elif alert_count >= 5:
            severity += 1

        return min(severity, 10)
