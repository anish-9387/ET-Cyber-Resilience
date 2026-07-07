import json
import hashlib
from typing import Dict, Any, Optional, List
from datetime import datetime
from app.core.logger import logger
from app.schemas.events import EventCreate, EventSeverity, EventCategory


class UnifiedEvent:
    def __init__(self, raw_event: Dict[str, Any], source: str):
        self.raw_event = raw_event
        self.source = source
        self.normalized: Dict[str, Any] = {}
        self.enrichments: Dict[str, Any] = {}
        self.processing_errors: List[str] = []

    def normalize(self) -> "UnifiedEvent":
        normalizers = {
            "windows": self._normalize_windows,
            "linux": self._normalize_linux,
            "syslog": self._normalize_syslog,
            "firewall": self._normalize_firewall,
            "wazuh": self._normalize_wazuh,
            "zeek": self._normalize_zeek,
            "suricata": self._normalize_suricata,
            "auditd": self._normalize_auditd,
            "cloudtrail": self._normalize_cloudtrail,
            "custom": self._normalize_custom
        }
        normalizer = normalizers.get(self.source, self._normalize_custom)
        try:
            self.normalized = normalizer()
        except Exception as e:
            self.processing_errors.append(f"Normalization failed: {str(e)}")
            self.normalized = self._normalize_custom()
        return self

    def _normalize_windows(self) -> Dict[str, Any]:
        e = self.raw_event
        return {
            "event_id": e.get("EventID") or e.get("EventId") or e.get("event_id"),
            "timestamp": e.get("TimeCreated") or e.get("timestamp") or datetime.utcnow().isoformat(),
            "source": "windows",
            "provider": e.get("Provider", {}).get("Name") if isinstance(e.get("Provider"), dict) else e.get("Provider"),
            "channel": e.get("Channel"),
            "computer": e.get("Computer") or e.get("computer"),
            "user": e.get("User") or e.get("user"),
            "event_type": self._classify_windows_event(e.get("EventID", 0)),
            "category": "system",
            "severity": self._map_windows_level(e.get("Level") or e.get("level", 4)),
            "title": f"Windows Event {e.get('EventID', 'unknown')}",
            "description": e.get("Message") or json.dumps(e.get("EventData", {})),
            "process_id": e.get("ProcessId") or e.get("process_id"),
            "thread_id": e.get("ThreadId"),
            "raw_data": e
        }

    def _classify_windows_event(self, event_id: int) -> str:
        if event_id in (4624, 4625, 4634, 4647, 4672):
            return "logon"
        elif event_id in (4688, 4689):
            return "process"
        elif event_id in (4656, 4663, 4658):
            return "object_access"
        elif event_id in (4697, 4698, 4699, 4700, 4701, 4702):
            return "service"
        elif event_id in (1102, 104):
            return "audit_log"
        elif event_id in (4720, 4722, 4723, 4724, 4725, 4726, 4738):
            return "account_management"
        elif event_id in (5140, 5142, 5143, 5144, 5145):
            return "share_access"
        elif event_id in (5152, 5154, 5155, 5156, 5157, 5158, 5159):
            return "firewall"
        return "other"

    def _map_windows_level(self, level: Optional[int]) -> str:
        mapping = {1: "critical", 2: "high", 3: "medium", 4: "low", 0: "info", 5: "info"}
        return mapping.get(level, "info")

    def _normalize_linux(self) -> Dict[str, Any]:
        e = self.raw_event
        return {
            "event_id": e.get("_id") or e.get("id") or hashlib.md5(json.dumps(e, default=str).encode()).hexdigest()[:16],
            "timestamp": e.get("timestamp") or e.get("@timestamp") or datetime.utcnow().isoformat(),
            "source": "linux",
            "hostname": e.get("hostname") or e.get("host") or e.get("host_name"),
            "user": e.get("user") or e.get("USER") or e.get("uid"),
            "event_type": e.get("type") or e.get("event_type", "unknown"),
            "category": "system",
            "severity": e.get("severity", "info"),
            "title": e.get("message", "")[:100] if e.get("message") else "Linux event",
            "description": e.get("message") or e.get("log") or "",
            "pid": e.get("pid") or e.get("process_id"),
            "command": e.get("command") or e.get("cmd") or e.get("COMMAND"),
            "raw_data": e
        }

    def _normalize_syslog(self) -> Dict[str, Any]:
        e = self.raw_event
        return {
            "event_id": e.get("_id") or hashlib.md5(json.dumps(e, default=str).encode()).hexdigest()[:16],
            "timestamp": e.get("timestamp") or e.get("date") or datetime.utcnow().isoformat(),
            "source": "syslog",
            "facility": e.get("facility"),
            "priority": e.get("priority"),
            "hostname": e.get("hostname") or e.get("host"),
            "event_type": "syslog",
            "category": "system",
            "severity": self._map_syslog_severity(e.get("severity") or e.get("level", 6)),
            "title": e.get("message", "")[:100] if e.get("message") else "Syslog event",
            "description": e.get("message") or "",
            "process": e.get("process") or e.get("app_name"),
            "raw_data": e
        }

    def _map_syslog_severity(self, sev) -> str:
        mapping = {"0": "critical", "1": "high", "2": "high", "3": "medium",
                   "4": "medium", "5": "low", "6": "info", "7": "info"}
        return mapping.get(str(sev), "info")

    def _normalize_firewall(self) -> Dict[str, Any]:
        e = self.raw_event
        return {
            "event_id": e.get("_id") or e.get("id"),
            "timestamp": e.get("timestamp") or datetime.utcnow().isoformat(),
            "source": "firewall",
            "device": e.get("device_name") or e.get("device") or e.get("firewall_name"),
            "action": e.get("action", "unknown"),
            "protocol": e.get("protocol"),
            "src_ip": e.get("src_ip") or e.get("source_ip") or e.get("src"),
            "dst_ip": e.get("dst_ip") or e.get("destination_ip") or e.get("dst"),
            "src_port": e.get("src_port") or e.get("source_port"),
            "dst_port": e.get("dst_port") or e.get("destination_port"),
            "event_type": "network",
            "category": "network",
            "severity": "high" if e.get("action") == "deny" else "low",
            "title": f"Firewall {e.get('action', 'unknown')} {e.get('protocol', '')}",
            "description": f"{e.get('action')} {e.get('protocol')} {e.get('src_ip')}:{e.get('src_port')} -> {e.get('dst_ip')}:{e.get('dst_port')}",
            "raw_data": e
        }

    def _normalize_wazuh(self) -> Dict[str, Any]:
        e = self.raw_event
        alert_data = e.get("data", {}) if isinstance(e.get("data"), dict) else {}
        return {
            "event_id": e.get("id") or e.get("_id") or alert_data.get("id"),
            "timestamp": e.get("timestamp") or e.get("@timestamp") or datetime.utcnow().isoformat(),
            "source": "wazuh",
            "agent": e.get("agent", {}).get("name") if isinstance(e.get("agent"), dict) else e.get("agent"),
            "agent_id": e.get("agent", {}).get("id") if isinstance(e.get("agent"), dict) else None,
            "rule_id": e.get("rule", {}).get("id") if isinstance(e.get("rule"), dict) else None,
            "rule_level": e.get("rule", {}).get("level", 0) if isinstance(e.get("rule"), dict) else 0,
            "rule_description": e.get("rule", {}).get("description") if isinstance(e.get("rule"), dict) else None,
            "event_type": "wazuh_alert",
            "category": "threat",
            "severity": self._map_wazuh_level(e.get("rule", {}).get("level", 0) if isinstance(e.get("rule"), dict) else 0),
            "title": (e.get("rule", {}).get("description") if isinstance(e.get("rule"), dict) else e.get("title")) or "Wazuh Alert",
            "description": e.get("full_log") or alert_data.get("log") or json.dumps(e),
            "location": e.get("location"),
            "raw_data": e
        }

    def _map_wazuh_level(self, level: int) -> str:
        if level >= 15: return "critical"
        if level >= 10: return "high"
        if level >= 7: return "medium"
        if level >= 4: return "low"
        return "info"

    def _normalize_zeek(self) -> Dict[str, Any]:
        e = self.raw_event
        return {
            "event_id": e.get("uid") or e.get("_id") or hashlib.md5(json.dumps(e, default=str).encode()).hexdigest()[:16],
            "timestamp": e.get("ts") or e.get("timestamp") or datetime.utcnow().isoformat(),
            "source": "zeek",
            "zeek_type": e.get("event_type") or e.get("_path") or "unknown",
            "protocol": e.get("proto") or e.get("protocol"),
            "src_ip": e.get("id.orig_h") or e.get("src_ip") or e.get("source_ip"),
            "src_port": e.get("id.orig_p") or e.get("src_port"),
            "dst_ip": e.get("id.resp_h") or e.get("dst_ip") or e.get("dest_ip"),
            "dst_port": e.get("id.resp_p") or e.get("dst_port"),
            "event_type": "zeek",
            "category": "network",
            "severity": e.get("severity", "info"),
            "title": f"Zeek {e.get('_path', 'event')}",
            "description": json.dumps({k: v for k, v in e.items() if k not in ("ts", "uid")}) if len(e) > 3 else str(e),
            "raw_data": e
        }

    def _normalize_suricata(self) -> Dict[str, Any]:
        e = self.raw_event
        alert = e.get("alert", {}) if isinstance(e.get("alert"), dict) else {}
        return {
            "event_id": e.get("event_id") or e.get("_id") or alert.get("signature_id"),
            "timestamp": e.get("timestamp") or datetime.utcnow().isoformat(),
            "source": "suricata",
            "event_type": e.get("event_type") or alert.get("category", "unknown"),
            "category": "network",
            "severity": self._map_suricata_severity(alert.get("severity", 3) if isinstance(alert, dict) else 3),
            "title": alert.get("signature") if isinstance(alert, dict) else "Suricata alert",
            "description": f"{alert.get('category', 'N/A')}: {alert.get('signature', 'N/A')}" if isinstance(alert, dict) else str(e),
            "src_ip": e.get("src_ip"),
            "dst_ip": e.get("dest_ip"),
            "src_port": e.get("src_port"),
            "dst_port": e.get("dest_port"),
            "protocol": e.get("proto") or e.get("protocol"),
            "raw_data": e
        }

    def _map_suricata_severity(self, severity: int) -> str:
        return {1: "critical", 2: "high", 3: "medium", 4: "low"}.get(severity, "info")

    def _normalize_auditd(self) -> Dict[str, Any]:
        e = self.raw_event
        return {
            "event_id": e.get("_id") or e.get("serial"),
            "timestamp": e.get("timestamp") or datetime.utcnow().isoformat(),
            "source": "auditd",
            "type": e.get("type"),
            "event_type": "audit",
            "category": "system",
            "severity": "medium",
            "title": f"auditd {e.get('type', 'event')}",
            "description": e.get("message") or json.dumps(e.get("data", {})),
            "user": e.get("user") or e.get("uid"),
            "pid": e.get("pid"),
            "command": e.get("comm") or e.get("exe"),
            "raw_data": e
        }

    def _normalize_cloudtrail(self) -> Dict[str, Any]:
        e = self.raw_event
        return {
            "event_id": e.get("eventID") or e.get("event_id"),
            "timestamp": e.get("eventTime") or e.get("timestamp") or datetime.utcnow().isoformat(),
            "source": "cloudtrail",
            "aws_region": e.get("awsRegion"),
            "event_type": "cloudtrail",
            "category": "system",
            "severity": "medium" if e.get("errorCode") else "info",
            "title": e.get("eventName", "CloudTrail Event"),
            "description": f"{e.get('eventName')} by {e.get('userIdentity', {}).get('arn', 'unknown')}" if isinstance(e.get("userIdentity"), dict) else e.get("eventName", ""),
            "user": e.get("userIdentity", {}).get("arn") if isinstance(e.get("userIdentity"), dict) else e.get("user"),
            "source_ip": e.get("sourceIPAddress"),
            "resources": e.get("resources", []),
            "raw_data": e
        }

    def _normalize_custom(self) -> Dict[str, Any]:
        e = self.raw_event
        return {
            "event_id": e.get("event_id") or e.get("id") or hashlib.md5(json.dumps(e, default=str).encode()).hexdigest()[:16],
            "timestamp": e.get("timestamp") or e.get("time") or e.get("date") or datetime.utcnow().isoformat(),
            "source": e.get("source", "custom"),
            "event_type": e.get("event_type") or e.get("type", "custom_event"),
            "category": e.get("category", "system"),
            "severity": e.get("severity", "info"),
            "title": e.get("title") or e.get("name") or e.get("summary", "Custom event"),
            "description": e.get("description") or e.get("message") or e.get("detail", ""),
            "raw_data": e
        }

    def to_event_create(self) -> EventCreate:
        n = self.normalized
        try:
            sev = EventSeverity(n.get("severity", "info"))
        except ValueError:
            sev = EventSeverity.INFO
        try:
            cat = EventCategory(n.get("category", "system"))
        except ValueError:
            cat = EventCategory.SYSTEM
        return EventCreate(
            event_type=n.get("event_type", "unknown"),
            category=cat,
            severity=sev,
            source=n.get("source", self.source),
            title=n.get("title", "Unprocessed event"),
            description=n.get("description", ""),
            raw_data=self.raw_event,
            metadata={**self.enrichments, "normalized": n},
            tags=[self.source, n.get("event_type", "unknown")]
        )


class EventProcessor:
    def __init__(self):
        self._enrichers = []

    def register_enricher(self, enricher_fn):
        self._enrichers.append(enricher_fn)

    async def process(self, raw_event: Dict[str, Any], source: str) -> UnifiedEvent:
        ue = UnifiedEvent(raw_event, source)
        ue.normalize()
        for enricher in self._enrichers:
            try:
                result = await enricher(ue.normalized) if hasattr(enricher, '__call__') else enricher(ue.normalized)
                if result:
                    ue.enrichments.update(result)
            except Exception as e:
                ue.processing_errors.append(f"Enricher failed: {str(e)}")
        logger.debug(
            "Processed %s event from %s (errors: %d)",
            ue.normalized.get("event_type", "unknown"), source, len(ue.processing_errors)
        )
        return ue

    async def process_batch(self, events: List[Dict[str, Any]], source: str) -> List[UnifiedEvent]:
        return [await self.process(e, source) for e in events]

    def get_stats(self) -> Dict[str, Any]:
        return {
            "enrichers_registered": len(self._enrichers),
            "supported_sources": [
                "windows", "linux", "syslog", "firewall",
                "wazuh", "zeek", "suricata", "auditd",
                "cloudtrail", "custom"
            ]
        }


event_processor = EventProcessor()
