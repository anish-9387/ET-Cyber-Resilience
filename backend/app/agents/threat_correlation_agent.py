from typing import Dict, Any, Optional, List, Tuple, Set
from datetime import datetime, timedelta
from collections import defaultdict, deque
from app.agents.base_agent import BaseAgent
from app.agents.mitre_mapper import mitre_mapper, TACTIC_ORDER
from app.core.logger import logger
import re
import hashlib


class TimeBasedCorrelator:
    def __init__(self, time_window_minutes: int = 30):
        self.time_window = timedelta(minutes=time_window_minutes)
        self.window_buffer: deque = deque()

    def add_event(self, event: Dict[str, Any]):
        self.window_buffer.append(event)
        self._cleanup()

    def _cleanup(self):
        now = datetime.utcnow()
        while self.window_buffer and self._get_event_time(self.window_buffer[0]) < now - self.time_window:
            self.window_buffer.popleft()

    def _get_event_time(self, event: Dict[str, Any]) -> datetime:
        ts = event.get("timestamp", event.get("time", datetime.utcnow().isoformat()))
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00")).replace(tzinfo=None)
            except (ValueError, TypeError):
                return datetime.utcnow()
        return ts if isinstance(ts, datetime) else datetime.utcnow()

    def correlate(self, reference_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        ref_time = self._get_event_time(reference_event)
        correlated = []
        for event in list(self.window_buffer):
            event_time = self._get_event_time(event)
            if event["event_id"] != reference_event.get("event_id") and \
               abs((event_time - ref_time).total_seconds()) <= self.time_window.total_seconds():
                correlated.append(event)
        return correlated


class SequenceDetector:
    def __init__(self):
        self.known_sequences = [
            ["phishing", "execution", "persistence"],
            ["initial_access", "execution", "privilege_escalation", "lateral_movement"],
            ["credential_access", "discovery", "lateral_movement"],
            ["execution", "defense_evasion", "persistence"],
            ["lateral_movement", "collection", "exfiltration"],
            ["persistence", "privilege_escalation", "defense_evasion", "credential_access"],
        ]

    def detect_sequence(self, events: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        if len(events) < 2:
            return None

        event_tactics = []
        for event in events:
            mapped = mitre_mapper.map_event(event)
            if mapped["mapped"] and mapped["tactic"]:
                tactic_lower = mapped["tactic"].lower().replace(" ", "_")
                event_tactics.append((event, tactic_lower))

        if len(event_tactics) < 2:
            return None

        detected_tactics = [t for _, t in event_tactics]

        for seq_idx, sequence in enumerate(self.known_sequences):
            match_len = 0
            seq_ptr = 0
            for tactic in detected_tactics:
                if seq_ptr < len(sequence) and tactic == sequence[seq_ptr]:
                    seq_ptr += 1
                    match_len += 1

            if match_len >= 2:
                progress = seq_ptr / len(sequence) if sequence else 0
                return {
                    "sequence_id": seq_idx,
                    "matched_sequence": sequence,
                    "match_length": match_len,
                    "sequence_length": len(sequence),
                    "progress": round(progress, 2),
                    "next_expected": sequence[seq_ptr] if seq_ptr < len(sequence) else "completed",
                }

        return None


class GraphBasedCorrelator:
    def __init__(self):
        self.entity_graph: Dict[str, Set[str]] = defaultdict(set)

    def add_relationship(self, source_entity: str, target_entity: str, relationship_type: str):
        key = f"{source_entity}:{relationship_type}"
        self.entity_graph[key].add(target_entity)

    def find_connected_events(self, entity: str, depth: int = 2) -> Set[str]:
        visited = {entity}
        queue = deque([(entity, 0)])
        connected = set()

        while queue:
            current, current_depth = queue.popleft()
            if current_depth >= depth:
                continue

            for key, targets in self.entity_graph.items():
                src, rel = key.split(":", 1)
                if src == current:
                    for target in targets:
                        if target not in visited:
                            visited.add(target)
                            connected.add(target)
                            queue.append((target, current_depth + 1))

                if current in targets:
                    if src not in visited:
                        visited.add(src)
                        connected.add(src)
                        queue.append((src, current_depth + 1))

        return connected


class ThreatCorrelationAgent(BaseAgent):
    def __init__(self, version: str = "1.0.0"):
        super().__init__(
            name="threat_correlation_agent",
            agent_type="threat_correlation",
            version=version,
        )
        self.time_correlator = TimeBasedCorrelator()
        self.sequence_detector = SequenceDetector()
        self.graph_correlator = GraphBasedCorrelator()
        self.correlated_threats: Dict[str, Dict[str, Any]] = {}
        self.event_buffer: List[Dict[str, Any]] = []

    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        self.last_run = datetime.utcnow()
        action = input_data.get("action", "correlate")

        try:
            if action == "ingest_event":
                return await self._ingest_event(input_data)
            elif action == "correlate":
                return await self._correlate(input_data)
            elif action == "correlate_all":
                return self._correlate_all()
            elif action == "get_threat":
                return self._get_threat(input_data)
            elif action == "get_active_threats":
                return self._get_active_threats()
            elif action == "add_relationship":
                return self._add_relationship(input_data)
            else:
                return {"success": False, "error": f"Unknown action: {action}"}
        except Exception as e:
            logger.error(f"ThreatCorrelationAgent error", error=str(e))
            self.update_metrics(False)
            return {"success": False, "error": str(e)}

    async def _ingest_event(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        event = input_data.get("event", input_data)
        if "event_id" not in event:
            event["event_id"] = hashlib.md5(str(event).encode()).hexdigest()[:12]
        if "timestamp" not in event:
            event["timestamp"] = datetime.utcnow().isoformat()

        self.event_buffer.append(event)
        self.time_correlator.add_event(event)

        source = event.get("source", event.get("entity_id", "unknown"))
        target = event.get("target", event.get("destination", "unknown"))
        if source != "unknown" and target != "unknown":
            rel_type = event.get("event_type", "related_to")
            self.graph_correlator.add_relationship(str(source), str(target), str(rel_type))

        mapped = mitre_mapper.map_event(event)
        if mapped["mapped"]:
            event["mitre"] = mapped

        await self.publish_event("threat.ingested", {
            "event_id": event["event_id"],
            "mapped": mapped["mapped"],
        })

        return {"success": True, "event_id": event["event_id"], "mitre_mapping": mapped}

    async def _correlate(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        reference_event = input_data.get("event", input_data)
        if "event_id" not in reference_event:
            reference_event["event_id"] = hashlib.md5(str(reference_event).encode()).hexdigest()[:12]

        time_correlated = self.time_correlator.correlate(reference_event)

        source_entity = str(reference_event.get("source", reference_event.get("entity_id", "")))
        graph_correlated = set()
        if source_entity:
            graph_correlated = self.graph_correlator.find_connected_events(source_entity)

        all_related = time_correlated
        graph_events = [e for e in self.event_buffer if e.get("event_id") in graph_correlated and
                        e["event_id"] != reference_event.get("event_id")]
        for ge in graph_events:
            if ge not in all_related:
                all_related.append(ge)

        sequence = self.sequence_detector.detect_sequence([reference_event] + all_related)

        threat_id = self._generate_threat_id(reference_event)
        threat = {
            "threat_id": threat_id,
            "primary_event_id": reference_event["event_id"],
            "primary_event_type": reference_event.get("event_type", "unknown"),
            "correlated_events": [e.get("event_id", "") for e in all_related[:50]],
            "correlation_count": len(all_related),
            "mitre_tactic": reference_event.get("mitre", {}).get("tactic", "unknown"),
            "technique_id": reference_event.get("mitre", {}).get("technique_id", "unknown"),
            "sequence": sequence,
            "tactic_index": self._get_tactic_index(reference_event.get("mitre", {}).get("tactic", "")),
            "severity": self._calculate_severity(reference_event, all_related),
            "timestamp": datetime.utcnow().isoformat(),
            "status": "active",
        }
        self.correlated_threats[threat_id] = threat

        if threat["severity"] >= 7:
            await self.publish_event("threat.critical", threat)

        return {"success": True, "threat": threat}

    def _correlate_all(self) -> Dict[str, Any]:
        active_threats = {}
        for event in self.event_buffer[-100:]:
            threat_data = self.time_correlator.correlate(event)
            if len(threat_data) >= 2:
                event_id = event.get("event_id", "")
                if event_id:
                    tid = self._generate_threat_id(event)
                    if tid not in active_threats:
                        active_threats[tid] = {
                            "threat_id": tid,
                            "events": [event_id] + [e.get("event_id", "") for e in threat_data[:10]],
                            "count": len(threat_data) + 1,
                            "detected_at": datetime.utcnow().isoformat(),
                        }
                    else:
                        active_threats[tid]["count"] += len(threat_data)

        return {
            "success": True,
            "total_threats": len(active_threats),
            "threats": list(active_threats.values()),
        }

    def _get_threat(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        threat_id = input_data.get("threat_id")
        if threat_id and threat_id in self.correlated_threats:
            return {"success": True, "threat": self.correlated_threats[threat_id]}
        return {"success": False, "error": "Threat not found"}

    def _get_active_threats(self) -> Dict[str, Any]:
        active = {tid: t for tid, t in self.correlated_threats.items() if t.get("status") == "active"}
        return {
            "success": True,
            "count": len(active),
            "threats": list(active.values()),
        }

    def _add_relationship(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        source = input_data.get("source")
        target = input_data.get("target")
        rel_type = input_data.get("relationship_type", "connected_to")
        if source and target:
            self.graph_correlator.add_relationship(str(source), str(target), str(rel_type))
            return {"success": True}
        return {"success": False, "error": "source and target required"}

    def _generate_threat_id(self, event: Dict[str, Any]) -> str:
        event_type = event.get("event_type", "unknown")
        technique_id = event.get("mitre", {}).get("technique_id", "NA")
        raw = f"{event_type}_{technique_id}_{datetime.utcnow().strftime('%Y%m%d%H')}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]

    def _get_tactic_index(self, tactic: str) -> int:
        tactic_lower = tactic.lower().replace(" ", "_")
        try:
            return TACTIC_ORDER.index(tactic_lower)
        except ValueError:
            return -1

    def _calculate_severity(self, primary: Dict[str, Any], related: List[Dict[str, Any]]) -> int:
        severity = 3
        if primary.get("mitre", {}).get("tactic", "") in {"impact", "exfiltration", "lateral_movement"}:
            severity += 3

        event_types = {e.get("event_type", "") for e in related if e.get("event_type")}
        dangerous_types = {"credential_dump", "lateral_movement", "ransomware", "data_exfil",
                           "privilege_escalation", "persistence"}
        overlap = event_types & dangerous_types
        severity += len(overlap) * 2

        if len(related) >= 5:
            severity += 2
        elif len(related) >= 3:
            severity += 1

        if severity > 10:
            severity = 10

        return severity
