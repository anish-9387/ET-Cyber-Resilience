"""Labelled benchmark corpus for the Overlook evaluation harness.

HONESTY STATEMENT
-----------------
The default corpus produced by :func:`generate_benchmark_dataset` is
**synthetic**. It is not a capture of real hospital traffic and no metric
derived from it should be presented as a real-world result. It is a
deterministic, seeded simulation whose purpose is to give the detector,
the ATT&CK mapper and the timing model a *labelled* substrate so their
behaviour can be measured reproducibly instead of asserted.

Seeded generation is correct here: this is dataset *synthesis*, not fake
inference. The seed is explicit (:data:`DEFAULT_SEED`), threaded through
``numpy.random.default_rng`` and ``random.Random``, and reported in the
provenance block of every evaluation payload.

Two deliberate design choices keep the benchmark from being trivially easy:

* Benign traffic contains **legitimately suspicious** activity - IT admins
  running ``wmic`` / ``net user`` for inventory, night-shift clinicians
  logging on at 03:00, backup jobs moving very large files. These are the
  real sources of false positives in a hospital SOC and they are labelled
  ``is_malicious=False``.
* Malicious traffic contains **quiet** steps (routine-looking SMB reads,
  a scheduled task) alongside loud ones (credential dumping). An evaluator
  that only fires on ``mimikatz`` will show poor recall, and it should.

Nothing is downloaded at import time.
"""

from __future__ import annotations

import csv
import random
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence

import numpy as np

try:
    # Preferred: the shared structlog logger used across the codebase.
    from app.core.logger import logger
except Exception:  # pragma: no cover - app.core eagerly builds a DB engine
    # app.core.__init__ constructs a SQLAlchemy engine at import time, which
    # makes the shared logger unavailable in a bare environment. The evaluation
    # harness must run standalone (no Postgres/Neo4j/Qdrant/Redis), so fall back
    # to an equivalent structlog logger rather than failing to import.
    import structlog

    logger = structlog.get_logger()

DEFAULT_SEED: int = 20260720

# Whether the concurrently-developed scenario module is importable. Guarded so
# this package remains testable standalone (no Postgres/Neo4j/Qdrant/Redis).
try:  # pragma: no cover - depends on a module owned by another agent
    from app.scenarios.apt_scenarios import SCENARIOS as _EXTERNAL_SCENARIOS

    SCENARIOS_AVAILABLE = True
except ImportError:  # pragma: no cover
    _EXTERNAL_SCENARIOS = None
    SCENARIOS_AVAILABLE = False


# --------------------------------------------------------------------------
# Record / dataset containers
# --------------------------------------------------------------------------


@dataclass
class LabeledRecord:
    """A single telemetry record carrying ground truth.

    The field names are chosen to match what
    ``BehaviourLearningAgent._detect_anomalies`` actually reads, so records can
    be fed to the real detector without a lossy translation layer.
    """

    record_id: str
    entity_id: str
    entity_type: str
    timestamp: datetime
    event_type: str
    source: str
    description: str
    #: Sensor-reported severity, used by the production likelihood-ratio
    #: derivation. Taken verbatim from the source telemetry where present;
    #: defaults to "info" so the harness never inflates an event's weight.
    severity: str = "info"

    # Detector-visible feature fields (optional per record, as in real telemetry)
    login_time: Optional[int] = None
    location: Optional[str] = None
    resource: Optional[str] = None
    command: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    data_size: Optional[int] = None
    day_of_week: Optional[int] = None

    # Ground truth
    is_malicious: bool = False
    true_technique: Optional[str] = None
    scenario_id: Optional[str] = None
    step_index: Optional[int] = None

    def to_event(self) -> Dict[str, Any]:
        """Project to the plain dict shape the detector and mapper consume."""
        event: Dict[str, Any] = {
            "entity_id": self.entity_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "source_type": self.source,
        }
        for key in (
            "login_time",
            "location",
            "resource",
            "command",
            "destination_ip",
            "port",
            "data_size",
            "day_of_week",
        ):
            value = getattr(self, key)
            if value is not None:
                event[key] = value
        return event

    def to_behaviour_input(self) -> Dict[str, Any]:
        """Project to the shape ``api.ingest.build_behaviour_input`` produces.

        ``to_event`` is the raw corpus projection. The production ingest path
        does two further things before handing an event to the behaviour agent,
        and a harness that skips them measures a *different* detector than the
        one that ships:

        1. It folds the event title/description into the ``command`` field, so
           the command rules also read the sensor's own narrative text
           ("Handle requested to lsass.exe memory by rundll32.exe comsvcs.dll
           MiniDump"). Most real telemetry carries the interesting strings
           there rather than in a structured command-line field.
        2. It maps Windows Event IDs onto behavioural event types via
           ``WINDOWS_BEHAVIOUR_EVENTS`` (4625 -> logon_failure, 1102 ->
           audit_log_cleared, ...). The corpus encodes the ID in the event type
           as ``windows_event_<id>``, so the same table is applied here.

        NOT replicated: ``severity``. Production passes the sensor's severity
        grading into the rule engine, but in this synthetic corpus every benign
        background record is ``info`` while malicious records carry
        critical/high/medium. Feeding severity to the detector here would hand
        it a near-perfect label proxy and inflate every metric for a reason that
        has nothing to do with the detector working. It is deliberately withheld
        so the reported numbers stay conservative; see the caveat emitted by
        ``detection_eval``.
        """
        from app.api.ingest import WINDOWS_BEHAVIOUR_EVENTS

        event = self.to_event()

        prefix = "windows_event_"
        if self.event_type.startswith(prefix):
            suffix = self.event_type[len(prefix):]
            if suffix.isdigit():
                mapped = WINDOWS_BEHAVIOUR_EVENTS.get(int(suffix))
                if mapped:
                    event["event_type"] = mapped

        combined = f"{event.get('command') or ''} {self.description or ''}".strip()
        if combined:
            event["command"] = combined[:1000]
        return event

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["timestamp"] = self.timestamp.isoformat()
        return payload


@dataclass
class BenchmarkDataset:
    """A labelled corpus plus the provenance needed to reproduce it."""

    records: List[LabeledRecord]
    provenance: Dict[str, Any] = field(default_factory=dict)

    def __len__(self) -> int:
        return len(self.records)

    @property
    def malicious(self) -> List[LabeledRecord]:
        return [r for r in self.records if r.is_malicious]

    @property
    def benign(self) -> List[LabeledRecord]:
        return [r for r in self.records if not r.is_malicious]

    @property
    def malicious_rate(self) -> float:
        if not self.records:
            return 0.0
        return len(self.malicious) / len(self.records)

    def scenario_ids(self) -> List[str]:
        seen: List[str] = []
        for record in self.records:
            if record.scenario_id and record.scenario_id not in seen:
                seen.append(record.scenario_id)
        return seen

    def by_scenario(self, scenario_id: str) -> List[LabeledRecord]:
        return [r for r in self.records if r.scenario_id == scenario_id]

    def split_by_time(self, train_fraction: float = 0.4) -> tuple[
        List[LabeledRecord], List[LabeledRecord]
    ]:
        """Chronological split.

        The training portion is drawn from the *earliest* window and is filtered
        to benign-only, mirroring how a behavioural baseline is actually built
        in production: you profile a period you believe to be clean. Using a
        random split would leak attack steps into the baseline and inflate the
        measured recall.
        """
        ordered = sorted(self.records, key=lambda r: r.timestamp)
        cut = int(len(ordered) * train_fraction)
        train = [r for r in ordered[:cut] if not r.is_malicious]
        evaluate = ordered[cut:]
        return train, evaluate

    def split_three_way(
        self,
        train_fraction: float = 0.4,
        calibration_fraction: float = 0.2,
    ) -> tuple[List[LabeledRecord], List[LabeledRecord], List[LabeledRecord]]:
        """Chronological baseline / calibration / holdout split.

        Anything the pipeline *learns a number from* must be fit on the
        calibration slice and reported on the holdout slice, or the reported
        metric is just the fit quality.

        * ``baseline`` - earliest window, benign-only (as ``split_by_time``).
          Fits the IsolationForest behavioural profiles.
        * ``calibration`` - next window, benign **and** malicious. Used to fit
          the likelihood-ratio mapping in ``api.ingest`` and to select the
          shipped decision threshold. Never scored in the headline metrics.
        * ``holdout`` - final window. The only slice the reported precision /
          recall / F1 / FPR / ROC-AUC are computed on.

        The split is chronological rather than random because the detector
        carries state (entity profiles) forward in time; a random split would
        let it profile an entity using events that occur after the one being
        scored.
        """
        ordered = sorted(self.records, key=lambda r: r.timestamp)
        train_cut = int(len(ordered) * train_fraction)
        calib_cut = train_cut + int(len(ordered) * calibration_fraction)
        baseline = [r for r in ordered[:train_cut] if not r.is_malicious]
        return baseline, ordered[train_cut:calib_cut], ordered[calib_cut:]


# --------------------------------------------------------------------------
# Hospital environment definition
# --------------------------------------------------------------------------

_CLINICAL_USERS = [
    "user.rn.avery", "user.rn.blake", "user.md.chen", "user.md.donovan",
    "user.rn.ellis", "user.md.farouk", "user.tech.gupta", "user.rn.hayes",
    "user.md.ibrahim", "user.tech.jansen", "user.rn.kowalski", "user.md.lin",
]
_IT_ADMINS = ["user.it.novak", "user.it.osei", "user.it.pereira"]
_SERVERS = [
    "srv-ehr-01", "srv-pacs-01", "srv-dc-01", "srv-backup-01",
    "srv-lab-01", "srv-pharmacy-01", "srv-file-01",
]
_WORKSTATIONS = [f"ws-ward{n:02d}" for n in range(1, 13)]

_BENIGN_RESOURCES = [
    "\\\\srv-file-01\\shared\\rota", "\\\\srv-ehr-01\\records\\daily",
    "\\\\srv-lab-01\\results", "\\\\srv-pharmacy-01\\formulary",
    "\\\\srv-pacs-01\\imaging\\today", "\\\\srv-file-01\\policies",
]
_BENIGN_DOMAINS = [
    "update.microsoft.com", "ehr-vendor.example.net", "ntp.pool.example.org",
    "pacs-vendor.example.com", "crl.digicert.example", "telemetry.epic.example",
]


# --------------------------------------------------------------------------
# Fallback scenario templates (used only when app.scenarios is unavailable)
# --------------------------------------------------------------------------

# Each step: (offset_minutes, event_type, technique, description, extra fields)
# Techniques deliberately include sub-technique IDs (e.g. T1021.002) because the
# real ATT&CK catalogue does, and the mapper's inability to resolve them is a
# measurable limitation we want surfaced rather than hidden.
_FALLBACK_SCENARIOS: List[Dict[str, Any]] = [
    {
        "scenario_id": "fallback-apt-ehr-ransom",
        "name": "Phishing to ransomware against the EHR estate",
        "steps": [
            {"offset_minutes": 0, "event_type": "phishing_email_opened",
             "technique": "T1566.001", "is_malicious": True,
             "description": "Clinician opened invoice attachment from external sender",
             "fields": {"resource": "mail\\inbox\\invoice_2026.docm"}},
            {"offset_minutes": 4, "event_type": "powershell_execution",
             "technique": "T1059.001", "is_malicious": True,
             "description": "Encoded PowerShell spawned by winword.exe",
             "fields": {"command": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"}},
            {"offset_minutes": 11, "event_type": "c2_beacon",
             "technique": "T1071.001", "is_malicious": True,
             "description": "Periodic HTTPS beacon to unrecognised host",
             "fields": {"destination_ip": "185.220.101.44", "port": 443, "data_size": 4096}},
            {"offset_minutes": 26, "event_type": "scheduled_task_created",
             "technique": "T1053.005", "is_malicious": True,
             "description": "Scheduled task registered for user-context persistence",
             "fields": {"command": "schtasks /create /tn UpdateCheck /tr c:\\users\\public\\u.exe"}},
            {"offset_minutes": 48, "event_type": "credential_dumping",
             "technique": "T1003.001", "is_malicious": True,
             "description": "LSASS memory access consistent with credential dumping",
             "fields": {"command": "mimikatz sekurlsa::logonpasswords"}},
            {"offset_minutes": 63, "event_type": "account_discovery",
             "technique": "T1087.002", "is_malicious": True,
             "description": "Domain account enumeration",
             "fields": {"command": "net group \"domain admins\" /domain"}},
            {"offset_minutes": 79, "event_type": "lateral_movement_smb",
             "technique": "T1021.002", "is_malicious": True,
             "description": "SMB admin share access to EHR server",
             "fields": {"resource": "\\\\srv-ehr-01\\c$", "destination_ip": "10.20.4.11"}},
            {"offset_minutes": 94, "event_type": "data_staging",
             "technique": "T1074.001", "is_malicious": True,
             "description": "Bulk patient records copied to staging directory",
             "fields": {"resource": "\\\\srv-ehr-01\\records\\confidential", "data_size": 880_000_000}},
            {"offset_minutes": 118, "event_type": "backup_deletion",
             "technique": "T1490", "is_malicious": True,
             "description": "Volume shadow copies deleted",
             "fields": {"command": "vssadmin delete shadows /all /quiet"}},
            {"offset_minutes": 126, "event_type": "ransomware_encryption",
             "technique": "T1486", "is_malicious": True,
             "description": "Mass file encryption across EHR shares",
             "fields": {"resource": "\\\\srv-ehr-01\\records", "data_size": 12_000_000_000}},
        ],
    },
    {
        "scenario_id": "fallback-apt-vpn-exfil",
        "name": "Edge exploitation to slow exfiltration of imaging data",
        "steps": [
            {"offset_minutes": 0, "event_type": "exploit_public_facing_app",
             "technique": "T1190", "is_malicious": True,
             "description": "Exploit attempt against unpatched VPN appliance",
             "fields": {"destination_ip": "203.0.113.77", "port": 443}},
            {"offset_minutes": 9, "event_type": "valid_accounts_vpn",
             "technique": "T1078.004", "is_malicious": True,
             "description": "VPN logon with service account from unfamiliar geography",
             "fields": {"location": "Sofia", "login_time": 3}},
            {"offset_minutes": 22, "event_type": "network_service_scanning",
             "technique": "T1046", "is_malicious": True,
             "description": "Internal port sweep from VPN concentrator",
             "fields": {"destination_ip": "10.20.4.0", "port": 445}},
            {"offset_minutes": 41, "event_type": "network_share_discovery",
             "technique": "T1135", "is_malicious": True,
             "description": "Enumeration of available SMB shares",
             "fields": {"command": "net view \\\\srv-pacs-01"}},
            {"offset_minutes": 58, "event_type": "impair_defenses",
             "technique": "T1562.001", "is_malicious": True,
             "description": "Endpoint protection service stopped on imaging host",
             "fields": {"command": "sc stop SentinelAgent"}},
            {"offset_minutes": 77, "event_type": "data_from_network_share",
             "technique": "T1039", "is_malicious": True,
             "description": "Bulk read of DICOM archive",
             "fields": {"resource": "\\\\srv-pacs-01\\imaging\\archive", "data_size": 2_400_000_000}},
            {"offset_minutes": 103, "event_type": "exfiltration_over_c2",
             "technique": "T1041", "is_malicious": True,
             "description": "Sustained outbound transfer to attacker infrastructure",
             "fields": {"destination_ip": "203.0.113.77", "port": 443, "data_size": 1_900_000_000}},
            {"offset_minutes": 140, "event_type": "indicator_removal",
             "technique": "T1070.001", "is_malicious": True,
             "description": "Windows event logs cleared on imaging host",
             "fields": {"command": "wevtutil cl Security"}},
        ],
    },
    {
        "scenario_id": "fallback-insider-pharmacy",
        "name": "Insider misuse of pharmacy and HR records",
        "steps": [
            {"offset_minutes": 0, "event_type": "valid_accounts",
             "technique": "T1078.002", "is_malicious": True,
             "description": "Pharmacy tech authenticates outside normal shift",
             "fields": {"login_time": 2, "location": "Hospital-Main"}},
            {"offset_minutes": 17, "event_type": "data_from_local_system",
             "technique": "T1005", "is_malicious": True,
             "description": "Access to HR compensation records unrelated to role",
             "fields": {"resource": "\\\\srv-file-01\\hr\\confidential\\salaries"}},
            {"offset_minutes": 35, "event_type": "email_collection",
             "technique": "T1114.001", "is_malicious": True,
             "description": "Bulk export of departmental mailbox",
             "fields": {"resource": "mail\\export\\pharmacy.pst", "data_size": 610_000_000}},
            {"offset_minutes": 52, "event_type": "exfil_removable_media",
             "technique": "T1052.001", "is_malicious": True,
             "description": "Large write to attached USB mass storage",
             "fields": {"event_type": "usb_insert", "data_size": 740_000_000}},
        ],
    },
]


def _get(obj: Any, *names: str, default: Any = None) -> Any:
    """Fetch the first present key/attribute from ``names``."""
    for name in names:
        if isinstance(obj, dict) and name in obj and obj[name] is not None:
            return obj[name]
        value = getattr(obj, name, None)
        if value is not None:
            return value
    return default


#: When a telemetry field is a nested object (e.g. Wazuh's ``agent``), these
#: keys are tried in order. Iterating ``dict.values()`` blindly is wrong: it
#: can return an opaque numeric id like "004" and fragment one host into
#: several distinct entities.
_NESTED_NAME_KEYS = ("name", "hostname", "host", "computer", "signature",
                     "description", "value", "id")


def _first_str(*values: Any) -> Optional[str]:
    """Return the first usable string, resolving nested objects by known keys."""
    for value in values:
        if isinstance(value, str) and value.strip():
            return value.strip()
        if isinstance(value, dict):
            for key in _NESTED_NAME_KEYS:
                nested = value.get(key)
                if isinstance(nested, str) and nested.strip():
                    return nested.strip()
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return str(value)
    return None


#: Severity words the production likelihood-ratio derivation understands
#: (``app.api.ingest.SEVERITY_MULTIPLIER``). Anything else must be translated,
#: not passed through: an unrecognised value silently falls back to a 1.0
#: multiplier, and a numeric scale like Wazuh's "15" would be discarded exactly
#: when the event matters most.
_KNOWN_SEVERITIES = ("critical", "high", "medium", "low", "info")


def _wazuh_level_to_severity(level: int) -> str:
    """Wazuh rule levels are 0-15. Banded per Wazuh's own documented tiers."""
    if level >= 12:
        return "critical"
    if level >= 8:
        return "high"
    if level >= 4:
        return "medium"
    return "low"


def _suricata_severity_to_severity(value: int) -> str:
    """Suricata alert severity is inverted: 1 is most severe, 4 least."""
    return {1: "high", 2: "medium", 3: "low"}.get(value, "info")


def _normalise_severity(event: Any, alert: Any, rule: Any) -> str:
    """Translate each source's severity convention into a common vocabulary.

    Returns ``"info"`` when a source reports no severity at all. That is the
    conservative choice - ``info`` carries the *smallest* likelihood-ratio
    multiplier (0.5x), so an unlabelled event is never allowed to inflate a
    belief.
    """
    explicit = _get(event, "severity", default=None)
    if isinstance(explicit, str) and explicit.strip().lower() in _KNOWN_SEVERITIES:
        return explicit.strip().lower()

    if isinstance(rule, dict) and rule.get("level") is not None:
        try:
            return _wazuh_level_to_severity(int(rule["level"]))
        except (TypeError, ValueError):
            pass

    if isinstance(alert, dict) and alert.get("severity") is not None:
        try:
            return _suricata_severity_to_severity(int(alert["severity"]))
        except (TypeError, ValueError):
            pass

    if isinstance(explicit, (int, float)) and not isinstance(explicit, bool):
        # A bare number with no source context: assume a Wazuh-style 0-15 scale
        # when it exceeds the Suricata range, otherwise treat it as Suricata's.
        value = int(explicit)
        return (
            _wazuh_level_to_severity(value) if value > 4
            else _suricata_severity_to_severity(value)
        )

    return "info"


def _normalise_external_event(event: Any, step_index: int) -> Optional[Dict[str, Any]]:
    """Flatten one raw scenario event into the fields the harness needs.

    ``app.scenarios.apt_scenarios`` emits genuinely heterogeneous telemetry -
    Windows Security XML-ish dicts, Zeek conn records, Suricata alerts, auditd,
    CloudTrail, firewall and Wazuh rows - each with its own field names. This
    maps them onto the common feature set that ``BehaviourLearningAgent`` and
    ``MitreMapper`` consume, without inventing values that are absent.

    Returns ``None`` if the event carries no ground-truth block, since an
    unlabelled event cannot be scored either way.
    """
    ground_truth = _get(event, "ground_truth", "groundTruth", default=None)
    if ground_truth is None:
        return None

    is_malicious = bool(_get(ground_truth, "is_malicious", default=False))
    technique = _get(ground_truth, "true_technique", "technique_id", default=None)

    # A malicious event with no technique label is unusable for attribution but
    # still valid for detection; keep it with technique=None rather than
    # guessing one.
    offset = _get(
        event, "offset_seconds", "offset_minutes", "time_offset_minutes",
        "t_offset", "offset", default=None,
    )
    if offset is None:
        offset_minutes = float(step_index * 5)
    else:
        try:
            offset_value = float(offset)
        except (TypeError, ValueError):
            offset_value = float(step_index * 5)
        # Prefer the explicit unit when the producer names it.
        if _get(event, "offset_seconds", default=None) is not None:
            offset_minutes = offset_value / 60.0
        elif offset_value > 60 * 24 * 7:  # implausible as minutes -> seconds
            offset_minutes = offset_value / 60.0
        else:
            offset_minutes = offset_value

    source = str(_get(event, "source_type", "source", default="unknown"))

    alert = _get(event, "alert", default={}) or {}
    rule = _get(event, "rule", default={}) or {}

    description = _first_str(
        _get(event, "description"),
        _get(event, "Message"),
        _get(event, "message"),
        alert.get("signature") if isinstance(alert, dict) else None,
        rule.get("description") if isinstance(rule, dict) else None,
        _get(event, "full_log"),
        _get(event, "eventName"),
    ) or "scenario event"

    event_type = _first_str(
        _get(event, "event_type"),
        _get(event, "type"),
        _get(event, "eventName"),
        alert.get("signature") if isinstance(alert, dict) else None,
    )
    if not event_type:
        event_id = _get(event, "EventID", "eventID")
        event_type = f"windows_event_{event_id}" if event_id else f"{source}_event"

    entity_id = _first_str(
        _get(event, "entity_id"),
        _get(event, "Computer"),
        _get(event, "hostname"),
        _get(event, "server_name"),
        _get(event, "User"),
        _get(event, "user"),
        _get(event, "agent"),
        _get(event, "id.orig_h"),
        _get(event, "src_ip"),
        _get(event, "sourceIPAddress"),
    ) or f"scenario-entity-{step_index}"

    user_like = _first_str(_get(event, "User"), _get(event, "user"))
    entity_type = "user" if user_like and user_like == entity_id else "device"

    command = _first_str(
        _get(event, "command_line"), _get(event, "comm"),
        _get(event, "CommandLine"),
    )
    request_params = _get(event, "requestParameters", default=None)
    if command is None and isinstance(request_params, dict):
        command = " ".join(f"{k}={v}" for k, v in request_params.items())[:400]

    fields: Dict[str, Any] = {
        "command": command,
        "resource": _first_str(_get(event, "resource"), _get(event, "_path")),
        "destination_ip": _first_str(
            _get(event, "dest_ip"), _get(event, "dst_ip"),
            _get(event, "id.resp_h"),
        ),
        "location": _first_str(_get(event, "location")),
    }

    port = _get(event, "dest_port", "dst_port", "id.resp_p", "src_port")
    if port is not None:
        try:
            fields["port"] = int(port)
        except (TypeError, ValueError):
            pass

    size = _get(event, "data_size", "orig_bytes", "resp_bytes")
    if size is not None:
        try:
            fields["data_size"] = int(float(size))
        except (TypeError, ValueError):
            pass

    fields = {k: v for k, v in fields.items() if v is not None}

    severity = _normalise_severity(event, alert, rule)

    return {
        "offset_minutes": offset_minutes,
        "event_type": str(event_type),
        "technique": str(technique) if technique else None,
        "description": description,
        "is_malicious": is_malicious,
        "source": source,
        "severity": str(severity).lower(),
        "entity_id": entity_id,
        "entity_type": entity_type,
        "fields": fields,
    }


def _normalise_external_scenarios(raw_scenarios: Any) -> List[Dict[str, Any]]:
    """Adapt ``app.scenarios.apt_scenarios.SCENARIOS`` to the internal shape.

    The scenario module is owned by another agent. This adapter is permissive
    about mapping vs attribute access and about field naming, and it preserves
    each event's own ``ground_truth`` rather than assuming every event in an
    attack scenario is malicious - the scenarios deliberately interleave benign
    activity, which is exactly the signal a false-positive measurement needs.
    """
    normalised: List[Dict[str, Any]] = []

    iterable: Iterable[Any]
    if isinstance(raw_scenarios, dict):
        iterable = raw_scenarios.values()
    else:
        iterable = raw_scenarios or []

    for index, scenario in enumerate(iterable):
        scenario_id = str(
            _get(scenario, "scenario_id", "id", "name", default=f"scenario-{index}")
        )
        raw_events = _get(scenario, "events", "steps", "timeline", default=[]) or []

        steps = []
        for step_index, event in enumerate(raw_events):
            step = _normalise_external_event(event, step_index)
            if step is not None:
                steps.append(step)

        if steps:
            normalised.append({
                "scenario_id": scenario_id,
                "name": str(_get(scenario, "name", default=scenario_id)),
                "actor": _get(scenario, "actor", default=None),
                "terminal_objective": _get(scenario, "terminal_objective", default=None),
                "steps": steps,
            })

    return normalised


def _active_scenarios() -> tuple[List[Dict[str, Any]], str]:
    """Return (scenarios, source_label)."""
    if SCENARIOS_AVAILABLE:
        try:
            adapted = _normalise_external_scenarios(_EXTERNAL_SCENARIOS)
            if adapted:
                return adapted, "app.scenarios.apt_scenarios"
            logger.warning(
                "evaluation.datasets: SCENARIOS imported but yielded no labelled "
                "steps; falling back to built-in templates"
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning(
                "evaluation.datasets: failed to adapt SCENARIOS",
                error=str(exc),
            )
    return _FALLBACK_SCENARIOS, "builtin_fallback_templates"


# --------------------------------------------------------------------------
# Benign background generation
# --------------------------------------------------------------------------


def _generate_benign_records(
    rng: np.random.Generator,
    pyrand: random.Random,
    start: datetime,
    count: int,
) -> List[LabeledRecord]:
    """Generate routine hospital telemetry.

    Includes a realistic minority of *legitimately unusual* activity so that
    false positives measured downstream are meaningful rather than a product of
    an artificially clean background.
    """
    records: List[LabeledRecord] = []

    for i in range(count):
        # Spread over ~14 days of operation.
        offset_minutes = float(rng.uniform(0, 14 * 24 * 60))
        timestamp = start + timedelta(minutes=offset_minutes)
        hour = timestamp.hour
        dow = timestamp.weekday()

        roll = rng.random()

        if roll < 0.34:
            # Clinical logon. Day shift dominates; night shift is real and rare.
            user = pyrand.choice(_CLINICAL_USERS)
            night_shift = rng.random() < 0.12
            login_hour = int(rng.integers(0, 6)) if night_shift else int(rng.integers(7, 20))
            records.append(LabeledRecord(
                record_id=f"benign-{i}",
                entity_id=user,
                entity_type="user",
                timestamp=timestamp,
                event_type="logon",
                source="windows",
                description="Interactive logon to clinical workstation",
                login_time=login_hour,
                location="Hospital-Main" if rng.random() > 0.05 else "Hospital-Annex",
                resource=pyrand.choice(_WORKSTATIONS),
                day_of_week=dow,
            ))

        elif roll < 0.55:
            # Routine SMB access to clinical shares.
            user = pyrand.choice(_CLINICAL_USERS)
            records.append(LabeledRecord(
                record_id=f"benign-{i}",
                entity_id=user,
                entity_type="user",
                timestamp=timestamp,
                event_type="smb_access",
                source="windows",
                description="Read access to clinical file share",
                resource=pyrand.choice(_BENIGN_RESOURCES),
                data_size=int(rng.integers(4_000, 8_000_000)),
                login_time=hour,
                day_of_week=dow,
            ))

        elif roll < 0.72:
            # DNS / vendor traffic.
            host = pyrand.choice(_WORKSTATIONS + _SERVERS)
            records.append(LabeledRecord(
                record_id=f"benign-{i}",
                entity_id=host,
                entity_type="device",
                timestamp=timestamp,
                event_type="dns_query",
                source="zeek",
                description=f"DNS resolution for {pyrand.choice(_BENIGN_DOMAINS)}",
                destination_ip=f"10.20.{int(rng.integers(1, 8))}.{int(rng.integers(2, 254))}",
                port=53,
                data_size=int(rng.integers(64, 1_400)),
                day_of_week=dow,
            ))

        elif roll < 0.83:
            # Patch / update traffic.
            host = pyrand.choice(_SERVERS + _WORKSTATIONS)
            records.append(LabeledRecord(
                record_id=f"benign-{i}",
                entity_id=host,
                entity_type="server" if host in _SERVERS else "device",
                timestamp=timestamp,
                event_type="patch_download",
                source="firewall",
                description="Vendor patch download over HTTPS",
                destination_ip="13.107.4.50",
                port=443,
                data_size=int(rng.integers(2_000_000, 400_000_000)),
                day_of_week=dow,
            ))

        elif roll < 0.91:
            # Scheduled maintenance jobs. Legitimate scheduled tasks.
            host = pyrand.choice(_SERVERS)
            records.append(LabeledRecord(
                record_id=f"benign-{i}",
                entity_id=host,
                entity_type="server",
                timestamp=timestamp,
                event_type="scheduled_task_run",
                source="windows",
                description="Nightly maintenance task executed",
                command=pyrand.choice([
                    "schtasks /run /tn NightlyIndex",
                    "schtasks /run /tn LabResultSync",
                    "schtasks /run /tn PharmacyReconcile",
                ]),
                login_time=int(rng.integers(0, 5)),
                day_of_week=dow,
            ))

        elif roll < 0.965:
            # IT admin maintenance -- genuinely benign but uses tooling that
            # overlaps with attacker tradecraft. A prime false-positive source.
            admin = pyrand.choice(_IT_ADMINS)
            records.append(LabeledRecord(
                record_id=f"benign-{i}",
                entity_id=admin,
                entity_type="user",
                timestamp=timestamp,
                event_type="admin_maintenance",
                source="sysmon",
                description="Scheduled asset inventory / account audit by IT",
                command=pyrand.choice([
                    "wmic product get name,version",
                    "net user /domain",
                    "net group \"Domain Users\" /domain",
                    "dsquery computer -limit 500",
                    "reg save HKLM\\SOFTWARE\\Inventory c:\\temp\\inv.hiv",
                ]),
                resource=pyrand.choice([
                    "\\\\srv-dc-01\\c$", "\\\\srv-file-01\\admin$",
                ]),
                login_time=int(rng.integers(6, 22)),
                day_of_week=dow,
            ))

        else:
            # Backup jobs: very large transfers, entirely legitimate.
            records.append(LabeledRecord(
                record_id=f"benign-{i}",
                entity_id="srv-backup-01",
                entity_type="server",
                timestamp=timestamp,
                event_type="backup_job",
                source="windows",
                description="Nightly backup replication to secondary site",
                resource="\\\\srv-backup-01\\vault",
                destination_ip="10.30.1.5",
                port=445,
                data_size=int(rng.integers(2_000_000_000, 20_000_000_000)),
                login_time=int(rng.integers(0, 4)),
                day_of_week=dow,
            ))

    return records


def _generate_scenario_records(
    scenarios: Sequence[Dict[str, Any]],
    rng: np.random.Generator,
    pyrand: random.Random,
    start: datetime,
    window_minutes: float,
) -> List[LabeledRecord]:
    """Instantiate each scenario at a random point inside the corpus window.

    Each step keeps its own ``is_malicious`` flag. Attack scenarios interleave
    benign activity, and mislabelling that benign activity as malicious would
    silently inflate recall and deflate the false positive rate.
    """
    records: List[LabeledRecord] = []

    for scenario in scenarios:
        scenario_id = scenario["scenario_id"]
        steps = scenario["steps"]
        max_offset = max((float(s["offset_minutes"]) for s in steps), default=0.0)
        latest_start = max(window_minutes - max_offset - 60.0, 0.0)
        scenario_start = start + timedelta(minutes=float(rng.uniform(0, latest_start)))

        # Fallback scenarios carry no entity identity of their own, so assign a
        # consistent victim per instantiation. External scenarios supply real
        # hostnames/usernames and those are preserved verbatim.
        victim_user = pyrand.choice(_CLINICAL_USERS)
        victim_host = pyrand.choice(_WORKSTATIONS)

        for step_index, step in enumerate(steps):
            offset_minutes = float(step["offset_minutes"])
            event_type = str(step["event_type"])
            timestamp = scenario_start + timedelta(minutes=offset_minutes)
            fields = dict(step.get("fields") or {})

            entity_id = step.get("entity_id")
            entity_type = step.get("entity_type")
            if not entity_id:
                if any(t in event_type for t in ("scan", "beacon", "exfil", "c2")):
                    entity_id, entity_type = victim_host, "device"
                else:
                    entity_id, entity_type = victim_user, "user"
            # Namespace external entity ids per instantiation so repeated
            # scenario runs do not collapse into one shared profile.
            entity_id = f"{entity_id}"

            records.append(LabeledRecord(
                record_id=f"scn-{scenario_id}-{step_index}",
                entity_id=entity_id,
                entity_type=entity_type or "device",
                timestamp=timestamp,
                event_type=event_type,
                source=str(step.get("source") or "sysmon"),
                description=str(step.get("description") or event_type),
                severity=str(step.get("severity") or "info").lower(),
                login_time=fields.pop("login_time", timestamp.hour),
                location=fields.pop("location", "Hospital-Main"),
                resource=fields.pop("resource", None),
                command=fields.pop("command", None),
                destination_ip=fields.pop("destination_ip", None),
                port=fields.pop("port", None),
                data_size=fields.pop("data_size", None),
                day_of_week=timestamp.weekday(),
                is_malicious=bool(step.get("is_malicious")),
                true_technique=step.get("technique"),
                scenario_id=scenario_id,
                step_index=step_index,
            ))

    return records


def generate_benchmark_dataset(
    seed: int = DEFAULT_SEED,
    benign_count: int = 4000,
    scenario_repeats: int = 4,
) -> BenchmarkDataset:
    """Build the deterministic synthetic benchmark corpus.

    Args:
        seed: Explicit RNG seed. The same seed always yields the same corpus.
        benign_count: Number of benign background records.
        scenario_repeats: How many times each APT scenario is instantiated at a
            different point in the timeline. Raising this raises the malicious
            class rate.

    Returns:
        A :class:`BenchmarkDataset` whose ``provenance`` records that the corpus
        is synthetic, the seed used, the scenario source, and the realised class
        balance. Target malicious rate is ~2-5%, matching the extreme class
        imbalance of real security telemetry.
    """
    rng = np.random.default_rng(seed)
    pyrand = random.Random(seed)

    start = datetime(2026, 6, 1, 0, 0, 0, tzinfo=timezone.utc)
    window_minutes = 14 * 24 * 60.0

    scenarios, scenario_source = _active_scenarios()

    background = _generate_benign_records(rng, pyrand, start, benign_count)

    scenario_records: List[LabeledRecord] = []
    for repeat in range(scenario_repeats):
        repeated = []
        for scenario in scenarios:
            clone = dict(scenario)
            clone["scenario_id"] = f"{scenario['scenario_id']}#{repeat}"
            repeated.append(clone)
        scenario_records.extend(
            _generate_scenario_records(repeated, rng, pyrand, start, window_minutes)
        )

    records = sorted(background + scenario_records, key=lambda r: r.timestamp)

    malicious = [r for r in records if r.is_malicious]
    benign = [r for r in records if not r.is_malicious]
    scenario_benign = sum(1 for r in scenario_records if not r.is_malicious)

    dataset = BenchmarkDataset(
        records=records,
        provenance={
            "dataset": "sentinel-synthetic-hospital-v1",
            "is_synthetic": True,
            "synthetic_disclaimer": (
                "Deterministic simulated hospital telemetry. NOT real capture "
                "data. Metrics derived from this corpus characterise detector "
                "behaviour on a simulation and must not be reported as "
                "real-world performance."
            ),
            "seed": seed,
            "scenario_source": scenario_source,
            "scenario_module_available": SCENARIOS_AVAILABLE,
            "scenario_repeats": scenario_repeats,
            "total_records": len(records),
            "benign_records": len(benign),
            "malicious_records": len(malicious),
            "malicious_rate": round(len(malicious) / max(len(records), 1), 5),
            "background_records": len(background),
            "scenario_records": len(scenario_records),
            "benign_records_inside_scenarios": scenario_benign,
            "malicious_records_with_technique_label": sum(
                1 for r in malicious if r.true_technique
            ),
            "distinct_scenarios": len({r.scenario_id for r in scenario_records}),
            "window_start": start.isoformat(),
            "window_days": 14,
        },
    )

    logger.info(
        "evaluation.datasets: generated synthetic corpus",
        total=len(records),
        malicious=len(malicious),
        malicious_rate=round(dataset.malicious_rate, 4),
        scenario_source=scenario_source,
        seed=seed,
    )
    return dataset


# --------------------------------------------------------------------------
# Real dataset adapter
# --------------------------------------------------------------------------

#: Column-name candidates for the label field across supported public datasets.
_LABEL_COLUMNS = ("Label", "label", "attack_cat", "sus", "evil", "class")
_BENIGN_LABEL_VALUES = {"benign", "normal", "0", "0.0", "", "none", "-"}


def load_external_dataset(
    path: str | Path,
    label_column: Optional[str] = None,
    technique_column: Optional[str] = None,
    max_rows: Optional[int] = None,
) -> BenchmarkDataset:
    """Load a real public benchmark from a local CSV the operator supplies.

    Nothing is downloaded. The caller must already have the file on disk.

    Supported / tested shapes
    -------------------------
    **CICIDS2017** (``MachineLearningCVE/*.csv``)
        Label column ``Label``. Benign rows are ``BENIGN``; everything else is
        an attack name (``DoS Hulk``, ``PortScan``, ``Web Attack - XSS`` ...).
        Flow features include ``Destination Port``, ``Flow Duration``,
        ``Total Fwd Packets``, ``Total Length of Fwd Packets``.

    **UNSW-NB15** (``UNSW_NB15_training-set.csv``)
        Label column ``label`` (0/1) with attack family in ``attack_cat``
        (``Fuzzers``, ``Exploits``, ``Reconnaissance``, ...). Feature columns
        include ``dur``, ``proto``, ``service``, ``sbytes``, ``dbytes``,
        ``dsport``.

    **BETH** (``labelled_*_data.csv``)
        Kernel-level process telemetry. Label columns ``sus`` and ``evil``
        (0/1); ``evil`` is the ground-truth attack flag. Feature columns
        include ``timestamp``, ``processName``, ``hostName``, ``eventName``,
        ``args``, ``userId``, ``processId``.

    Mapping applied
    ---------------
    ``is_malicious`` is derived from ``label_column`` (auto-detected from
    :data:`_LABEL_COLUMNS` when not given): a row is benign iff its label value
    lowercases into :data:`_BENIGN_LABEL_VALUES`.

    ``true_technique`` is only populated if ``technique_column`` is supplied and
    contains ATT&CK IDs. **None of these three datasets ship ATT&CK technique
    labels**, so attribution accuracy cannot be computed from them without an
    operator-provided mapping. The loader does not invent one; it leaves
    ``true_technique`` as ``None`` and attribution evaluation will report the
    records as unscorable rather than guessing.

    Raises:
        FileNotFoundError: if ``path`` does not exist.
        ValueError: if no usable label column can be found.
    """
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"External dataset not found: {path}")

    records: List[LabeledRecord] = []
    resolved_label_column = label_column

    with path.open("r", newline="", encoding="utf-8", errors="replace") as handle:
        reader = csv.DictReader(handle)
        fieldnames = [f.strip() for f in (reader.fieldnames or [])]

        if resolved_label_column is None:
            for candidate in _LABEL_COLUMNS:
                if candidate in fieldnames:
                    resolved_label_column = candidate
                    break
        if resolved_label_column is None:
            raise ValueError(
                f"No label column found in {path}. Columns present: {fieldnames}. "
                f"Pass label_column= explicitly."
            )

        base_time = datetime(2026, 1, 1, tzinfo=timezone.utc)
        for index, row in enumerate(reader):
            if max_rows is not None and index >= max_rows:
                break
            clean = {(k.strip() if k else k): v for k, v in row.items()}
            raw_label = str(clean.get(resolved_label_column, "")).strip()
            is_malicious = raw_label.lower() not in _BENIGN_LABEL_VALUES

            technique = None
            if technique_column:
                technique = clean.get(technique_column) or None

            records.append(LabeledRecord(
                record_id=f"ext-{index}",
                entity_id=str(
                    clean.get("hostName")
                    or clean.get("Source IP")
                    or clean.get("srcip")
                    or f"row-{index}"
                ),
                entity_type="device",
                timestamp=base_time + timedelta(seconds=index),
                event_type=str(clean.get("eventName") or raw_label or "flow"),
                source=path.name,
                description=f"{path.name} row {index}",
                destination_ip=clean.get("Destination IP") or clean.get("dstip"),
                port=_safe_int(clean.get("Destination Port") or clean.get("dsport")),
                data_size=_safe_int(
                    clean.get("Total Length of Fwd Packets") or clean.get("sbytes")
                ),
                is_malicious=is_malicious,
                true_technique=technique,
                scenario_id=raw_label if is_malicious else None,
            ))

    malicious_count = sum(1 for r in records if r.is_malicious)
    labelled_techniques = sum(1 for r in records if r.true_technique)

    logger.info(
        "evaluation.datasets: loaded external dataset",
        path=str(path),
        rows=len(records),
        malicious=malicious_count,
    )

    return BenchmarkDataset(
        records=records,
        provenance={
            "dataset": path.name,
            "is_synthetic": False,
            "source_path": str(path),
            "seed": None,
            "label_column": resolved_label_column,
            "technique_column": technique_column,
            "total_records": len(records),
            "malicious_records": malicious_count,
            "malicious_rate": round(malicious_count / max(len(records), 1), 5),
            "records_with_attack_technique_labels": labelled_techniques,
            "attribution_scorable": labelled_techniques > 0,
            "note": (
                "CICIDS2017 / UNSW-NB15 / BETH do not ship ATT&CK technique "
                "labels; attribution accuracy is not computable from them "
                "without an operator-supplied technique mapping."
            ),
        },
    )


def _safe_int(value: Any) -> Optional[int]:
    if value in (None, ""):
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None
