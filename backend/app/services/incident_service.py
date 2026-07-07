from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from app.core.logger import logger
from app.schemas.incidents import (
    IncidentCreate, IncidentUpdate, IncidentResponse,
    IncidentStatus, IncidentSeverity, IncidentPriority,
    IncidentType, IncidentTimelineEntry, IncidentSummary
)
from app.core.database import get_db
from app.core.config import settings
from sqlalchemy import text


class IncidentSLA:
    RESPONSE_TIMES = {
        IncidentPriority.P0: timedelta(minutes=15),
        IncidentPriority.P1: timedelta(minutes=30),
        IncidentPriority.P2: timedelta(hours=4),
        IncidentPriority.P3: timedelta(hours=8),
        IncidentPriority.P4: timedelta(hours=24),
    }

    RESOLUTION_TIMES = {
        IncidentPriority.P0: timedelta(hours=4),
        IncidentPriority.P1: timedelta(hours=8),
        IncidentPriority.P2: timedelta(hours=24),
        IncidentPriority.P3: timedelta(hours=72),
        IncidentPriority.P4: timedelta(hours=168),
    }

    @classmethod
    def get_response_deadline(cls, priority: IncidentPriority) -> datetime:
        return datetime.utcnow() + cls.RESPONSE_TIMES.get(priority, timedelta(hours=4))

    @classmethod
    def get_resolution_deadline(cls, priority: IncidentPriority) -> datetime:
        return datetime.utcnow() + cls.RESOLUTION_TIMES.get(priority, timedelta(hours=24))

    @classmethod
    def check_sla_breach(cls, created_at: datetime, priority: IncidentPriority) -> Dict[str, Any]:
        now = datetime.utcnow()
        response_deadline = created_at + cls.RESPONSE_TIMES.get(priority, timedelta(hours=4))
        resolution_deadline = created_at + cls.RESOLUTION_TIMES.get(priority, timedelta(hours=24))
        return {
            "response_breached": now > response_deadline,
            "resolution_breached": now > resolution_deadline,
            "response_deadline": response_deadline.isoformat(),
            "resolution_deadline": resolution_deadline.isoformat(),
            "time_remaining_response": str(response_deadline - now) if now < response_deadline else "Overdue",
            "time_remaining_resolution": str(resolution_deadline - now) if now < resolution_deadline else "Overdue"
        }


class SeverityCalculator:
    WEIGHTS = {
        "ransomware": 1.0, "data_breach": 0.9, "dos": 0.7,
        "malware": 0.6, "network_intrusion": 0.6, "unauthorized_access": 0.5,
        "insider_threat": 0.5, "phishing": 0.3, "policy_violation": 0.2, "other": 0.1
    }

    @classmethod
    def calculate(cls, incident_type: IncidentType, alert_count: int = 1, asset_criticality: float = 0.5) -> IncidentSeverity:
        base = cls.WEIGHTS.get(incident_type, 0.1)
        alert_factor = min(alert_count / 10, 1.0)
        score = base * 0.5 + alert_factor * 0.3 + asset_criticality * 0.2
        if score >= 0.8: return IncidentSeverity.CRITICAL
        if score >= 0.6: return IncidentSeverity.HIGH
        if score >= 0.4: return IncidentSeverity.MEDIUM
        return IncidentSeverity.LOW

    @classmethod
    def calculate_priority(cls, severity: IncidentSeverity) -> IncidentPriority:
        mapping = {
            IncidentSeverity.CRITICAL: IncidentPriority.P0,
            IncidentSeverity.HIGH: IncidentPriority.P1,
            IncidentSeverity.MEDIUM: IncidentPriority.P2,
            IncidentSeverity.LOW: IncidentPriority.P3
        }
        return mapping.get(severity, IncidentPriority.P3)


class IncidentService:
    def __init__(self):
        self._incidents: Dict[str, Dict[str, Any]] = {}
        self._timelines: Dict[str, List[Dict[str, Any]]] = {}

    async def create(self, incident_data: IncidentCreate, created_by: str = "system") -> IncidentResponse:
        import uuid
        incident_id = str(uuid.uuid4())
        now = datetime.utcnow()
        incident = {
            "id": incident_id,
            "title": incident_data.title,
            "description": incident_data.description,
            "incident_type": incident_data.incident_type.value,
            "status": IncidentStatus.NEW.value,
            "severity": incident_data.severity.value,
            "priority": incident_data.priority.value,
            "source": incident_data.source,
            "affected_assets": incident_data.affected_assets or [],
            "mitre_techniques": incident_data.mitre_techniques or [],
            "indicators": incident_data.indicators or [],
            "assigned_to": incident_data.assigned_to,
            "tags": incident_data.tags or [],
            "resolution_notes": None,
            "created_by": created_by,
            "created_at": now.isoformat(),
            "updated_at": now.isoformat(),
            "resolved_at": None,
            "sla": IncidentSLA.check_sla_breach(now, incident_data.priority)
        }
        self._incidents[incident_id] = incident
        self._add_timeline_entry(incident_id, "created", created_by, "Incident created")
        logger.info("Incident %s created: %s", incident_id, incident_data.title)
        return IncidentResponse(**incident)

    async def get(self, incident_id: str) -> Optional[IncidentResponse]:
        incident = self._incidents.get(incident_id)
        if incident:
            incident["sla"] = IncidentSLA.check_sla_breach(
                datetime.fromisoformat(incident["created_at"]),
                IncidentPriority(incident["priority"])
            )
            return IncidentResponse(**incident)
        return None

    async def update(self, incident_id: str, update_data: IncidentUpdate, actor: str = "system") -> Optional[IncidentResponse]:
        incident = self._incidents.get(incident_id)
        if not incident:
            return None
        update_dict = update_data.model_dump(exclude_unset=True)
        for key, value in update_dict.items():
            if value is not None:
                incident[key] = value
                if key == "status":
                    self._add_timeline_entry(incident_id, "status_change", actor, f"Status changed to {value}")
                elif key == "assigned_to":
                    self._add_timeline_entry(incident_id, "assignment", actor, f"Assigned to {value}")
        incident["updated_at"] = datetime.utcnow().isoformat()
        if update_dict.get("status") in ("resolved", "closed"):
            incident["resolved_at"] = datetime.utcnow().isoformat()
        return IncidentResponse(**incident)

    async def add_evidence(self, incident_id: str, evidence: Dict[str, Any], actor: str = "system") -> bool:
        if incident_id not in self._incidents:
            return False
        self._incidents[incident_id].setdefault("evidence", []).append({
            **evidence, "added_by": actor, "added_at": datetime.utcnow().isoformat()
        })
        self._add_timeline_entry(incident_id, "evidence_added", actor, "Evidence added")
        return True

    async def add_comment(self, incident_id: str, comment: str, actor: str = "system") -> bool:
        if incident_id not in self._incidents:
            return False
        self._incidents[incident_id].setdefault("comments", []).append({
            "text": comment, "author": actor, "timestamp": datetime.utcnow().isoformat()
        })
        return True

    async def get_timeline(self, incident_id: str) -> List[Dict[str, Any]]:
        return self._timelines.get(incident_id, [])

    async def list_incidents(self, status: Optional[IncidentStatus] = None, severity: Optional[IncidentSeverity] = None, priority: Optional[IncidentPriority] = None, assigned_to: Optional[str] = None, limit: int = 50) -> List[IncidentSummary]:
        results = []
        for inc in self._incidents.values():
            if status and inc["status"] != status.value:
                continue
            if severity and inc["severity"] != severity.value:
                continue
            if priority and inc["priority"] != priority.value:
                continue
            if assigned_to and inc.get("assigned_to") != assigned_to:
                continue
            created = datetime.fromisoformat(inc["created_at"])
            results.append(IncidentSummary(
                id=inc["id"], title=inc["title"], status=IncidentStatus(inc["status"]),
                severity=IncidentSeverity(inc["severity"]), priority=IncidentPriority(inc["priority"]),
                incident_type=IncidentType(inc["incident_type"]), created_at=created,
                assigned_to=inc.get("assigned_to"), age_hours=(datetime.utcnow() - created).total_seconds() / 3600
            ))
        results.sort(key=lambda x: ({"critical": 0, "high": 1, "medium": 2, "low": 3}.get(x.severity.value, 4), x.created_at))
        return results[:limit]

    async def get_stats(self) -> Dict[str, Any]:
        total = len(self._incidents)
        by_status = {}
        by_severity = {}
        by_type = {}
        open_count = 0
        for inc in self._incidents.values():
            inc_type = inc.get("incident_type", "other")
            by_type[inc_type] = by_type.get(inc_type, 0) + 1
            by_status[inc["status"]] = by_status.get(inc["status"], 0) + 1
            by_severity[inc["severity"]] = by_severity.get(inc["severity"], 0) + 1
            if inc["status"] not in ("resolved", "closed", "false_positive"):
                open_count += 1
        return {
            "total_incidents": total, "open_incidents": open_count,
            "by_status": by_status, "by_severity": by_severity, "by_type": by_type
        }

    async def link_alerts(self, incident_id: str, alert_ids: List[str]) -> bool:
        if incident_id not in self._incidents:
            return False
        self._incidents[incident_id].setdefault("linked_alerts", []).extend(alert_ids)
        self._add_timeline_entry(incident_id, "alerts_linked", "system", f"Linked {len(alert_ids)} alerts")
        return True

    def _add_timeline_entry(self, incident_id: str, action: str, actor: str, description: str):
        if incident_id not in self._timelines:
            self._timelines[incident_id] = []
        self._timelines[incident_id].append({
            "incident_id": incident_id, "action": action, "actor": actor,
            "description": description, "timestamp": datetime.utcnow().isoformat()
        })


incident_service = IncidentService()
