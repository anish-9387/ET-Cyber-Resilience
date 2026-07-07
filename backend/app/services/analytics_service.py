import statistics
from typing import Dict, Any, Optional, List
from datetime import datetime, timedelta
from collections import defaultdict
from app.core.logger import logger
from app.core.config import settings


class MetricsCalculator:
    def __init__(self):
        self._events: List[Dict[str, Any]] = []
        self._incidents: List[Dict[str, Any]] = []
        self._response_times: List[float] = []
        self._detection_times: List[float] = []
        self._investigation_times: List[float] = []
        self._daily_counts: Dict[str, int] = defaultdict(int)
        self._severity_distribution: Dict[str, int] = defaultdict(int)
        self._source_distribution: Dict[str, int] = defaultdict(int)

    def record_event(self, event: Dict[str, Any]):
        self._events.append(event)
    def record_incident(self, incident: Dict[str, Any]):
        self._incidents.append(incident)

    def record_detection_time(self, minutes: float):
        self._detection_times.append(minutes)
    def record_response_time(self, minutes: float):
        self._response_times.append(minutes)
    def record_investigation_time(self, minutes: float):
        self._investigation_times.append(minutes)

    def mean_time_to_detect(self) -> Dict[str, Any]:
        if not self._detection_times:
            return {"mttd_minutes": 0, "mttd_hours": 0, "sample_count": 0}
        mttd = statistics.mean(self._detection_times)
        return {
            "mttd_minutes": round(mttd, 2), "mttd_hours": round(mttd / 60, 2),
            "median_minutes": round(statistics.median(self._detection_times), 2),
            "min_minutes": round(min(self._detection_times), 2),
            "max_minutes": round(max(self._detection_times), 2),
            "p95_minutes": round(sorted(self._detection_times)[int(len(self._detection_times) * 0.95)], 2) if len(self._detection_times) > 1 else 0,
            "sample_count": len(self._detection_times)
        }

    def mean_time_to_respond(self) -> Dict[str, Any]:
        if not self._response_times:
            return {"mttr_minutes": 0, "mttr_hours": 0, "sample_count": 0}
        mttr = statistics.mean(self._response_times)
        return {
            "mttr_minutes": round(mttr, 2), "mttr_hours": round(mttr / 60, 2),
            "median_minutes": round(statistics.median(self._response_times), 2),
            "min_minutes": round(min(self._response_times), 2),
            "max_minutes": round(max(self._response_times), 2),
            "p95_minutes": round(sorted(self._response_times)[int(len(self._response_times) * 0.95)], 2) if len(self._response_times) > 1 else 0,
            "sample_count": len(self._response_times)
        }

    def mean_time_to_investigate(self) -> Dict[str, Any]:
        if not self._investigation_times:
            return {"mtti_minutes": 0, "mtti_hours": 0, "sample_count": 0}
        mtti = statistics.mean(self._investigation_times)
        return {
            "mtti_minutes": round(mtti, 2), "mtti_hours": round(mtti / 60, 2),
            "median_minutes": round(statistics.median(self._investigation_times), 2),
            "min_minutes": round(min(self._investigation_times), 2),
            "max_minutes": round(max(self._investigation_times), 2),
            "sample_count": len(self._investigation_times)
        }

    def event_trend(self, days: int = 30) -> Dict[str, Any]:
        cutoff = datetime.utcnow() - timedelta(days=days)
        recent = [e for e in self._events if datetime.fromisoformat(e.get("timestamp", datetime.utcnow().isoformat())) >= cutoff]
        daily = defaultdict(int)
        for e in recent:
            day = datetime.fromisoformat(e.get("timestamp", datetime.utcnow().isoformat())).strftime("%Y-%m-%d")
            daily[day] += 1
        sorted_days = sorted(daily.keys())
        return {
            "period_days": days, "total_events": len(recent),
            "daily_average": round(len(recent) / max(days, 1), 2),
            "daily_breakdown": {d: daily[d] for d in sorted_days[-30:]},
            "trend": "increasing" if len(sorted_days) > 1 and daily.get(sorted_days[-1], 0) > daily.get(sorted_days[0], 0) else "stable"
        }

    def incident_trend(self, days: int = 30) -> Dict[str, Any]:
        cutoff = datetime.utcnow() - timedelta(days=days)
        recent = [i for i in self._incidents if datetime.fromisoformat(i.get("created_at", datetime.utcnow().isoformat())) >= cutoff]
        by_severity = defaultdict(int)
        for inc in recent:
            by_severity[inc.get("severity", "low")] += 1
        return {
            "period_days": days, "total_incidents": len(recent),
            "by_severity": dict(by_severity),
            "open_incidents": sum(1 for i in recent if i.get("status") not in ("resolved", "closed", "false_positive"))
        }

    def sla_compliance(self) -> Dict[str, Any]:
        breached = sum(1 for inc in self._incidents if inc.get("sla_breached"))
        total = len(self._incidents)
        return {
            "total_incidents": total, "sla_breaches": breached,
            "compliance_rate": round((1 - breached / max(total, 1)) * 100, 2) if total else 100.0
        }

    def top_indicators(self, limit: int = 10) -> List[Dict[str, int]]:
        indicator_counts = defaultdict(int)
        for inc in self._incidents:
            for ind in inc.get("indicators", []):
                indicator_counts[ind] += 1
        sorted_indicators = sorted(indicator_counts.items(), key=lambda x: x[1], reverse=True)
        return [{"indicator": i, "count": c} for i, c in sorted_indicators[:limit]]

    def summary(self) -> Dict[str, Any]:
        return {
            "mttd": self.mean_time_to_detect(),
            "mttr": self.mean_time_to_respond(),
            "mtti": self.mean_time_to_investigate(),
            "sla_compliance": self.sla_compliance(),
            "event_trend_7d": self.event_trend(days=7),
            "incident_trend_30d": self.incident_trend(days=30),
            "total_events_processed": len(self._events),
            "total_incidents_created": len(self._incidents),
            "top_indicators": self.top_indicators(limit=5)
        }


class ReportGenerator:
    def __init__(self):
        self._templates = {
            "executive": self._executive_summary,
            "incident": self._incident_report,
            "trend": self._trend_report,
            "compliance": self._compliance_report
        }

    def generate(self, report_type: str, metrics: MetricsCalculator, params: Dict[str, Any] = None) -> Dict[str, Any]:
        generator = self._templates.get(report_type, self._executive_summary)
        return generator(metrics, params or {})

    def _executive_summary(self, metrics: MetricsCalculator, params: Dict[str, Any]) -> Dict[str, Any]:
        s = metrics.summary()
        return {
            "report_type": "executive_summary",
            "generated_at": datetime.utcnow().isoformat(),
            "period": params.get("period", "Last 30 days"),
            "key_findings": [
                f"MTTD: {s['mttd']['mttd_hours']} hours",
                f"MTTR: {s['mttr']['mttr_hours']} hours",
                f"SLA Compliance: {s['sla_compliance']['compliance_rate']}%",
                f"Total Incidents: {s['total_incidents_created']}",
                f"Total Events: {s['total_events_processed']}"
            ],
            "metrics": s
        }

    def _incident_report(self, metrics: MetricsCalculator, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "report_type": "incident_report",
            "generated_at": datetime.utcnow().isoformat(),
            "incident_id": params.get("incident_id"),
            "timeline": [],
            "metrics": {
                "detection_time": metrics.mean_time_to_detect(),
                "response_time": metrics.mean_time_to_respond(),
                "investigation_time": metrics.mean_time_to_investigate()
            }
        }

    def _trend_report(self, metrics: MetricsCalculator, params: Dict[str, Any]) -> Dict[str, Any]:
        days = params.get("days", 30)
        return {
            "report_type": "trend_report",
            "generated_at": datetime.utcnow().isoformat(),
            "period_days": days,
            "event_trend": metrics.event_trend(days),
            "incident_trend": metrics.incident_trend(days),
            "top_indicators": metrics.top_indicators(limit=10)
        }

    def _compliance_report(self, metrics: MetricsCalculator, params: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "report_type": "compliance_report",
            "generated_at": datetime.utcnow().isoformat(),
            "sla": metrics.sla_compliance(),
            "metrics": metrics.summary(),
            "framework": params.get("framework", "SOC 2")
        }


class AnalyticsService:
    def __init__(self):
        self.metrics = MetricsCalculator()
        self.reports = ReportGenerator()

    def track_event(self, event: Dict[str, Any]):
        self.metrics.record_event(event)

    def track_incident(self, incident: Dict[str, Any]):
        self.metrics.record_incident(incident)
        if incident.get("created_at") and incident.get("detected_at"):
            detection = (datetime.fromisoformat(incident["created_at"]) - datetime.fromisoformat(incident["detected_at"])).total_seconds() / 60
            self.metrics.record_detection_time(detection)
        if incident.get("resolved_at") and incident.get("created_at"):
            response = (datetime.fromisoformat(incident["resolved_at"]) - datetime.fromisoformat(incident["created_at"])).total_seconds() / 60
            self.metrics.record_response_time(response)

    def get_metrics(self) -> Dict[str, Any]:
        return self.metrics.summary()

    def generate_report(self, report_type: str = "executive", params: Dict[str, Any] = None) -> Dict[str, Any]:
        return self.reports.generate(report_type, self.metrics, params)

    def get_dashboard_data(self) -> Dict[str, Any]:
        s = self.metrics.summary()
        return {
            "mttd": s["mttd"]["mttd_hours"],
            "mttr": s["mttr"]["mttr_hours"],
            "mtti": s["mtti"]["mtti_hours"],
            "sla_compliance": s["sla_compliance"]["compliance_rate"],
            "total_events": s["total_events_processed"],
            "total_incidents": s["total_incidents_created"],
            "event_trend": s["event_trend_7d"],
            "incident_trend": s["incident_trend_30d"],
            "top_indicators": s["top_indicators"]
        }


analytics_service = AnalyticsService()
