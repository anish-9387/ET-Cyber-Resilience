import json
import aiohttp
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, Any, Optional, List, Callable
from datetime import datetime
from enum import Enum
from app.core.logger import logger
from app.core.config import settings


class NotificationChannel(str, Enum):
    EMAIL = "email"
    SLACK = "slack"
    TEAMS = "teams"
    WEBHOOK = "webhook"
    SMS = "sms"


class NotificationPriority(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class NotificationTemplate:
    def __init__(self):
        self._templates: Dict[str, str] = {
            "alert": {
                "subject": "[{severity}] Overlook Alert: {title}",
                "body": "Alert Details\n{separator}\nTitle: {title}\nSeverity: {severity}\nSource: {source}\nTime: {timestamp}\nDescription: {description}\n\nAction Required: {action_url}"
            },
            "incident_created": {
                "subject": "[{priority}] Incident Created: {title}",
                "body": "Incident Details\n{separator}\nID: {incident_id}\nTitle: {title}\nSeverity: {severity}\nPriority: {priority}\nType: {incident_type}\nAssigned To: {assigned_to}\nCreated: {timestamp}\n\nView: {action_url}"
            },
            "incident_updated": {
                "subject": "Incident Updated: {title}",
                "body": "Incident Updated\n{separator}\nID: {incident_id}\nTitle: {title}\nStatus: {status}\nUpdated By: {actor}\n\nView: {action_url}"
            },
            "sla_breach": {
                "subject": "[CRITICAL] SLA Breach: {incident_id}",
                "body": "SLA Breach Alert\n{separator}\nIncident: {title}\nPriority: {priority}\nDeadline: {deadline}\nElapsed: {elapsed}\n\nImmediate action required: {action_url}"
            },
            "daily_digest": {
                "subject": "Overlook Daily Digest - {date}",
                "body": "Daily Digest\n{separator}\nDate: {date}\nNew Incidents: {new_incidents}\nResolved: {resolved}\nOpen: {open}\nAlerts: {alerts}\n\nReview: {action_url}"
            },
            "test": {
                "subject": "Overlook Test Notification",
                "body": "This is a test notification from Overlook.\nTime: {timestamp}"
            }
        }

    def render(self, template_name: str, context: Dict[str, Any]) -> Dict[str, str]:
        template = self._templates.get(template_name, self._templates["alert"])
        separator = "=" * 40
        context["separator"] = separator
        context["action_url"] = context.get("action_url", settings.APP_URL) if hasattr(settings, "APP_URL") else "http://localhost:3000"
        context["timestamp"] = context.get("timestamp", datetime.utcnow().isoformat())
        try:
            subject = template["subject"].format(**context)
            body = template["body"].format(**context)
        except KeyError as e:
            logger.warning("Template rendering missing key: %s", e)
            subject = template["subject"]
            body = template["body"]
        return {"subject": subject, "body": body, "template": template_name}

    def register_template(self, name: str, subject_template: str, body_template: str):
        self._templates[name] = {"subject": subject_template, "body": body_template}


class EscalationPolicy:
    def __init__(self):
        self._levels: List[Dict[str, Any]] = [
            {"level": 1, "name": "Primary", "delay_minutes": 0, "notify_channels": ["email", "slack"]},
            {"level": 2, "name": "Secondary", "delay_minutes": 15, "notify_channels": ["email", "slack", "teams"]},
            {"level": 3, "name": "Tertiary", "delay_minutes": 30, "notify_channels": ["email", "slack", "teams", "sms"]},
            {"level": 4, "name": "Management", "delay_minutes": 60, "notify_channels": ["email", "sms", "webhook"]}
        ]
        self._escalation_contacts: Dict[int, List[Dict[str, str]]] = {}

    def set_contacts(self, level: int, contacts: List[Dict[str, str]]):
        self._escalation_contacts[level] = contacts

    def get_escalation_path(self, priority: NotificationPriority) -> List[Dict[str, Any]]:
        if priority == NotificationPriority.CRITICAL:
            return self._levels
        elif priority == NotificationPriority.HIGH:
            return self._levels[:3]
        elif priority == NotificationPriority.MEDIUM:
            return self._levels[:2]
        return self._levels[:1]

    def get_contacts(self, level: int) -> List[Dict[str, str]]:
        return self._escalation_contacts.get(level, [{"name": "SOC Team", "email": "soc@sentinelx.local"}])


class EmailSender:
    def __init__(self):
        self.smtp_host = getattr(settings, "SMTP_HOST", "localhost")
        self.smtp_port = getattr(settings, "SMTP_PORT", 587)
        self.smtp_user = getattr(settings, "SMTP_USER", "")
        self.smtp_password = getattr(settings, "SMTP_PASSWORD", "")
        self.from_addr = getattr(settings, "FROM_EMAIL", "sentinel-x@localhost")
        self._enabled = bool(self.smtp_host and self.smtp_host != "localhost")

    async def send(self, to: List[str], subject: str, body: str, html: Optional[str] = None) -> bool:
        if not self._enabled:
            logger.info("Email disabled: would send to %s: %s", to, subject)
            return True
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = self.from_addr
            msg["To"] = ", ".join(to)
            msg.attach(MIMEText(body, "plain"))
            if html:
                msg.attach(MIMEText(html, "html"))
            with smtplib.SMTP(self.smtp_host, self.smtp_port) as server:
                if self.smtp_user:
                    server.starttls()
                    server.login(self.smtp_user, self.smtp_password)
                server.sendmail(self.from_addr, to, msg.as_string())
            logger.info("Email sent to %s: %s", to, subject)
            return True
        except Exception as e:
            logger.error("Email send failed: %s", str(e))
            return False


class SlackSender:
    def __init__(self):
        self.webhook_url = getattr(settings, "SLACK_WEBHOOK_URL", "")
        self._enabled = bool(self.webhook_url)

    async def send(self, channel: str, subject: str, body: str) -> bool:
        if not self._enabled:
            logger.info("Slack disabled: would send to #%s: %s", channel, subject)
            return True
        try:
            payload = {
                "channel": f"#{channel}",
                "username": "Overlook",
                "icon_emoji": ":shield:",
                "attachments": [{
                    "color": self._get_color(body),
                    "title": subject,
                    "text": body,
                    "footer": "Overlook Notification",
                    "ts": datetime.utcnow().timestamp()
                }]
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload, timeout=10) as resp:
                    if resp.status != 200:
                        logger.warning("Slack returned %d", resp.status)
                    return resp.status == 200
        except Exception as e:
            logger.error("Slack send failed: %s", str(e))
            return False

    def _get_color(self, body: str) -> str:
        if "CRITICAL" in body or "critical" in body: return "#FF0000"
        if "HIGH" in body or "high" in body: return "#FF6600"
        if "MEDIUM" in body or "medium" in body: return "#FFD700"
        return "#36A64F"


class TeamsSender:
    def __init__(self):
        self.webhook_url = getattr(settings, "TEAMS_WEBHOOK_URL", "")
        self._enabled = bool(self.webhook_url)

    async def send(self, subject: str, body: str) -> bool:
        if not self._enabled:
            logger.info("Teams disabled: would send: %s", subject)
            return True
        try:
            payload = {
                "@type": "MessageCard",
                "@context": "http://schema.org/extensions",
                "themeColor": self._get_color(body),
                "summary": subject,
                "sections": [{
                    "activityTitle": subject,
                    "activitySubtitle": f"Overlook | {datetime.utcnow().isoformat()}",
                    "text": body,
                    "markdown": True
                }]
            }
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload, timeout=10) as resp:
                    return resp.status == 200
        except Exception as e:
            logger.error("Teams send failed: %s", str(e))
            return False

    def _get_color(self, body: str) -> str:
        if "CRITICAL" in body: return "ff0000"
        if "HIGH" in body: return "ff6600"
        if "MEDIUM" in body: return "ffd700"
        return "36a64f"


class WebhookSender:
    def __init__(self):
        self._webhooks: List[Dict[str, Any]] = []

    def register(self, name: str, url: str, headers: Dict[str, str] = None, secret: str = None):
        self._webhooks.append({
            "name": name, "url": url, "headers": headers or {},
            "secret": secret, "enabled": True
        })

    def unregister(self, name: str):
        self._webhooks = [w for w in self._webhooks if w["name"] != name]

    async def send(self, name: str, payload: Dict[str, Any]) -> bool:
        targets = [w for w in self._webhooks if w["name"] == name] if name else self._webhooks
        if not targets:
            logger.info("No webhook targets for: %s", name or "all")
            return False
        success = True
        async with aiohttp.ClientSession() as session:
            for webhook in targets:
                if not webhook["enabled"]:
                    continue
                try:
                    headers = {**webhook["headers"], "Content-Type": "application/json"}
                    if webhook.get("secret"):
                        headers["X-Webhook-Secret"] = webhook["secret"]
                    async with session.post(webhook["url"], json=payload, headers=headers, timeout=10) as resp:
                        if resp.status >= 400:
                            logger.warning("Webhook %s returned %d", webhook["name"], resp.status)
                            success = False
                except Exception as e:
                    logger.error("Webhook %s failed: %s", webhook["name"], str(e))
                    success = False
        return success


class SMSSender:
    def __init__(self):
        self.provider = getattr(settings, "SMS_PROVIDER", "twilio")
        self.api_key = getattr(settings, "SMS_API_KEY", "")
        self.from_number = getattr(settings, "SMS_FROM_NUMBER", "")
        self._enabled = bool(self.api_key and self.from_number)

    async def send(self, to: str, message: str) -> bool:
        if not self._enabled:
            logger.info("SMS disabled: would send to %s: %s", to, message[:50])
            return True
        try:
            if self.provider == "twilio":
                async with aiohttp.ClientSession() as session:
                    payload = {"To": to, "From": self.from_number, "Body": message}
                    auth = aiohttp.BasicAuth(self.api_key, getattr(settings, "SMS_API_SECRET", ""))
                    async with session.post(
                        f"https://api.twilio.com/2010-04-01/Accounts/{self.api_key}/Messages.json",
                        data=payload, auth=auth, timeout=10
                    ) as resp:
                        return resp.status == 201
            logger.info("SMS sent via %s to %s", self.provider, to)
            return True
        except Exception as e:
            logger.error("SMS send failed: %s", str(e))
            return False


class NotificationService:
    def __init__(self):
        self.templates = NotificationTemplate()
        self.escalation = EscalationPolicy()
        self.email = EmailSender()
        self.slack = SlackSender()
        self.teams = TeamsSender()
        self.webhook = WebhookSender()
        self.sms = SMSSender()
        self._channels: Dict[str, Callable] = {
            "email": self._send_email,
            "slack": self._send_slack,
            "teams": self._send_teams,
            "webhook": self._send_webhook,
            "sms": self._send_sms
        }
        self._notification_log: List[Dict[str, Any]] = []

    async def send(self, template_name: str, context: Dict[str, Any], channels: Optional[List[str]] = None, priority: NotificationPriority = NotificationPriority.MEDIUM):
        rendered = self.templates.render(template_name, context)
        target_channels = channels or self._resolve_channels(priority)
        results = {}
        for channel in target_channels:
            sender = self._channels.get(channel)
            if sender:
                success = await sender(rendered, context)
                results[channel] = {"success": success, "sent_at": datetime.utcnow().isoformat()}
            else:
                results[channel] = {"success": False, "error": "Unknown channel"}
        self._log_notification(template_name, context, target_channels, results)
        if priority in (NotificationPriority.HIGH, NotificationPriority.CRITICAL):
            await self._run_escalation(template_name, context, priority, results)
        return results

    async def send_alert(self, alert: Dict[str, Any]):
        context = {
            "title": alert.get("title", "Alert"),
            "severity": alert.get("severity", "medium").upper(),
            "source": alert.get("source", "unknown"),
            "description": alert.get("description", ""),
            "alert_id": alert.get("id", ""),
            "timestamp": alert.get("timestamp", datetime.utcnow().isoformat())
        }
        priority = self._map_severity_to_priority(alert.get("severity", "medium"))
        return await self.send("alert", context, priority=priority)

    async def send_incident_notification(self, incident: Dict[str, Any], event: str = "created"):
        template_map = {
            "created": "incident_created", "updated": "incident_updated",
            "sla_breach": "sla_breach"
        }
        template_name = template_map.get(event, "incident_created")
        context = {
            "incident_id": incident.get("id", ""),
            "title": incident.get("title", ""),
            "severity": incident.get("severity", "medium").upper(),
            "priority": incident.get("priority", "p2").upper(),
            "incident_type": incident.get("incident_type", ""),
            "assigned_to": incident.get("assigned_to", "Unassigned"),
            "status": incident.get("status", ""),
            "description": incident.get("description", ""),
            "deadline": incident.get("sla", {}).get("response_deadline", ""),
            "elapsed": incident.get("sla", {}).get("time_remaining_response", ""),
            "actor": incident.get("updated_by", "system"),
            "timestamp": incident.get("created_at", datetime.utcnow().isoformat())
        }
        priority = self._map_severity_to_priority(incident.get("severity", "medium"))
        return await self.send(template_name, context, priority=priority)

    async def send_daily_digest(self, stats: Dict[str, Any]):
        context = {
            "date": datetime.utcnow().strftime("%Y-%m-%d"),
            "new_incidents": stats.get("new_incidents", 0),
            "resolved": stats.get("resolved", 0),
            "open": stats.get("open", 0),
            "alerts": stats.get("alerts", 0)
        }
        return await self.send("daily_digest", context, channels=["email", "slack"], priority=NotificationPriority.LOW)

    async def send_test(self, channel: str) -> Dict[str, Any]:
        context = {"timestamp": datetime.utcnow().isoformat()}
        rendered = self.templates.render("test", context)
        sender = self._channels.get(channel)
        if not sender:
            return {"success": False, "error": f"Unknown channel: {channel}"}
        success = await sender(rendered, context)
        return {"channel": channel, "success": success}

    def _resolve_channels(self, priority: NotificationPriority) -> List[str]:
        if priority == NotificationPriority.CRITICAL:
            return ["email", "slack", "teams", "sms"]
        elif priority == NotificationPriority.HIGH:
            return ["email", "slack", "teams"]
        elif priority == NotificationPriority.MEDIUM:
            return ["email", "slack"]
        return ["email"]

    def _map_severity_to_priority(self, severity: str) -> NotificationPriority:
        mapping = {
            "critical": NotificationPriority.CRITICAL,
            "high": NotificationPriority.HIGH,
            "medium": NotificationPriority.MEDIUM,
            "low": NotificationPriority.LOW,
            "info": NotificationPriority.LOW
        }
        return mapping.get(severity.lower(), NotificationPriority.MEDIUM)

    async def _run_escalation(self, template_name: str, context: Dict[str, Any], priority: NotificationPriority, initial_results: Dict[str, Any]):
        escalation_path = self.escalation.get_escalation_path(priority)
        for level in escalation_path:
            if level["level"] == 1:
                continue
            contacts = self.escalation.get_contacts(level["level"])
            logger.info("Escalation level %d (%s) triggered, notifying %d contacts", level["level"], level["name"], len(contacts))

    async def _send_email(self, rendered: Dict[str, Any], context: Dict[str, Any]) -> bool:
        to = context.get("to", getattr(settings, "NOTIFICATION_EMAILS", ["soc@sentinelx.local"]))
        if isinstance(to, str):
            to = [to]
        return await self.email.send(to, rendered["subject"], rendered["body"])

    async def _send_slack(self, rendered: Dict[str, Any], context: Dict[str, Any]) -> bool:
        channel = context.get("slack_channel", "alerts")
        return await self.slack.send(channel, rendered["subject"], rendered["body"])

    async def _send_teams(self, rendered: Dict[str, Any], context: Dict[str, Any]) -> bool:
        return await self.teams.send(rendered["subject"], rendered["body"])

    async def _send_webhook(self, rendered: Dict[str, Any], context: Dict[str, Any]) -> bool:
        target = context.get("webhook_name", "")
        payload = {
            "event": "notification",
            "template": rendered.get("template", "unknown"),
            "subject": rendered["subject"],
            "body": rendered["body"],
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": context
        }
        return await self.webhook.send(target, payload)

    async def _send_sms(self, rendered: Dict[str, Any], context: Dict[str, Any]) -> bool:
        to = context.get("sms_to", getattr(settings, "SMS_TO_NUMBER", ""))
        if not to:
            return False
        body = f"{rendered['subject']}\n{rendered['body'][:150]}"
        return await self.sms.send(to, body)

    def _log_notification(self, template_name: str, context: Dict[str, Any], channels: List[str], results: Dict[str, Any]):
        self._notification_log.append({
            "template": template_name, "context_keys": list(context.keys()),
            "channels": channels, "results": results,
            "timestamp": datetime.utcnow().isoformat()
        })
        if len(self._notification_log) > 1000:
            self._notification_log = self._notification_log[-500:]

    def get_log(self, limit: int = 50) -> List[Dict[str, Any]]:
        return self._notification_log[-limit:]

    def get_stats(self) -> Dict[str, Any]:
        total = len(self._notification_log)
        success = sum(1 for n in self._notification_log if any(r.get("success") for r in n["results"].values()))
        by_channel = {}
        for n in self._notification_log:
            for ch, result in n["results"].items():
                if ch not in by_channel:
                    by_channel[ch] = {"sent": 0, "success": 0}
                by_channel[ch]["sent"] += 1
                if result.get("success"):
                    by_channel[ch]["success"] += 1
        return {
            "total_notifications": total,
            "successful": success,
            "failed": total - success,
            "success_rate": round(success / max(total, 1) * 100, 2),
            "by_channel": by_channel,
            "channels_enabled": {
                "email": self.email._enabled,
                "slack": self.slack._enabled,
                "teams": self.teams._enabled,
                "sms": self.sms._enabled
            }
        }


notification_service = NotificationService()
