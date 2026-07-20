from typing import Dict, Any, Optional, List, Tuple
from difflib import SequenceMatcher
import re

from app.core.logger import logger


TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$", re.IGNORECASE)

#: Minimum string similarity for the last-resort fuzzy name match.
#:
#: The keyword table below is the designed mapping path and covers the
#: `[rule: ...]` tags real Sigma/SIEM detections carry. Fuzzy name matching is
#: only a fallback, and at the previous 0.3 threshold it fired on almost
#: anything - a benign Windows logon matched "Email Collection" (T1114) - which
#: injects phantom techniques into attribution and objective scoring.
FUZZY_MATCH_THRESHOLD = 0.75

#: Confidence for an exact keyword/rule-tag hit, the designed mapping path.
KEYWORD_MATCH_CONFIDENCE = 0.85


def normalize_technique_id(value: Any) -> Optional[str]:
    """Return the canonical parent technique id, or None if this is not one.

    ATT&CK sub-technique ids (`T1486.001`) collapse to their parent (`T1486`)
    so that observation streams and the scoring tables - which are keyed on
    parent techniques - compare on the same alphabet. Sentinel values such as
    `"UNKNOWN"`, `None` or free text return None so they can never be counted
    as an observed technique.
    """
    if not value:
        return None
    candidate = str(value).strip().upper()
    if not TECHNIQUE_ID_RE.match(candidate):
        return None
    return candidate.split(".", 1)[0]


MITRE_ATTACK_DATA = {
    "initial_access": {
        "T1566": {"name": "Phishing", "tactic": "Initial Access", "detection": ["Email gateway logs", "User reports", "URL analysis"]},
        "T1078": {"name": "Valid Accounts", "tactic": "Initial Access", "detection": ["Authentication logs", "Anomalous login patterns"]},
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "detection": ["WAF logs", "IDS/IPS alerts", "Application logs"]},
        "T1133": {"name": "External Remote Services", "tactic": "Initial Access", "detection": ["VPN logs", "RDP logs", "SSH logs"]},
        "T1091": {"name": "Replication Through Removable Media", "tactic": "Initial Access", "detection": ["USB device logs", "Antivirus alerts"]},
    },
    "execution": {
        "T1204": {"name": "User Execution", "tactic": "Execution", "detection": ["Process creation logs", "Office telemetry"]},
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "detection": ["PowerShell logs", "Bash history", "Script block logging"]},
        "T1106": {"name": "Native API", "tactic": "Execution", "detection": ["API monitoring", "Sysmon event ID 1"]},
        "T1569": {"name": "System Services", "tactic": "Execution", "detection": ["Service creation logs", "Sysmon event ID 11"]},
    },
    "persistence": {
        "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": "Persistence", "detection": ["Registry monitoring", "Startup folder monitoring"]},
        "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence", "detection": ["Task scheduler logs", "Cron monitoring"]},
        "T1098": {"name": "Account Manipulation", "tactic": "Persistence", "detection": ["Account admin events", "Group membership changes"]},
        "T1136": {"name": "Create Account", "tactic": "Persistence", "detection": ["User account creation events"]},
        "T1505": {"name": "Server Software Component", "tactic": "Persistence", "detection": ["Web shell detection", "IIS module monitoring"]},
    },
    "privilege_escalation": {
        "T1055": {"name": "Process Injection", "tactic": "Privilege Escalation", "detection": ["API call monitoring", "Memory forensics"]},
        "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": "Privilege Escalation", "detection": ["Exploit detection", "Kernel call monitoring"]},
        "T1078": {"name": "Valid Accounts", "tactic": "Privilege Escalation", "detection": ["Privileged account usage anomalies"]},
        "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "detection": ["UAC bypass detection", "sudo monitoring"]},
    },
    "defense_evasion": {
        "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion", "detection": ["AV/EDR service stop events", "Firewall rule changes"]},
        "T1070": {"name": "Indicator Removal", "tactic": "Defense Evasion", "detection": ["Log clearing events", "File deletion auditing"]},
        "T1036": {"name": "Masquerading", "tactic": "Defense Evasion", "detection": ["Process name analysis", "Digital signature verification"]},
        "T1055": {"name": "Process Injection", "tactic": "Defense Evasion", "detection": ["Cross-process access monitoring"]},
        "T1112": {"name": "Modify Registry", "tactic": "Defense Evasion", "detection": ["Registry auditing", "Sysmon event 12/13/14"]},
    },
    "credential_access": {
        "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "detection": ["LSASS access monitoring", "Mimikatz detection"]},
        "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access", "detection": ["Password manager audit logs"]},
        "T1056": {"name": "Input Capture", "tactic": "Credential Access", "detection": ["Keylogger detection", "API hooking detection"]},
        "T1110": {"name": "Brute Force", "tactic": "Credential Access", "detection": ["Failed login monitoring", "Account lockout events"]},
        "T1552": {"name": "Unsecured Credentials", "tactic": "Credential Access", "detection": ["File share scanning", "Configuration file auditing"]},
    },
    "discovery": {
        "T1087": {"name": "Account Discovery", "tactic": "Discovery", "detection": ["AD enumeration logs", "Net command monitoring"]},
        "T1069": {"name": "Permission Groups Discovery", "tactic": "Discovery", "detection": ["Group enumeration monitoring"]},
        "T1082": {"name": "System Information Discovery", "tactic": "Discovery", "detection": ["Host information query monitoring"]},
        "T1046": {"name": "Network Service Scanning", "tactic": "Discovery", "detection": ["Port scan detection", "Network flow analysis"]},
        "T1135": {"name": "Network Share Discovery", "tactic": "Discovery", "detection": ["Share enumeration monitoring"]},
    },
    "lateral_movement": {
        "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "detection": ["RDP/SSH/WinRM connection logs"]},
        "T1550": {"name": "Use Alternate Authentication Material", "tactic": "Lateral Movement", "detection": ["Pass-the-hash detection", "Kerberos ticket anomalies"]},
        "T1570": {"name": "Lateral Tool Transfer", "tactic": "Lateral Movement", "detection": ["File transfer monitoring", "SMB/WebDAV logs"]},
        "T1091": {"name": "Replication Through Removable Media", "tactic": "Lateral Movement", "detection": ["USB device events"]},
    },
    "collection": {
        "T1005": {"name": "Data from Local System", "tactic": "Collection", "detection": ["File access auditing", "Data staging detection"]},
        "T1039": {"name": "Data from Network Shared Drive", "tactic": "Collection", "detection": ["SMB file access logs", "Bulk file enumeration"]},
        "T1114": {"name": "Email Collection", "tactic": "Collection", "detection": ["Mailbox access auditing", "EWS API monitoring"]},
        "T1056": {"name": "Input Capture", "tactic": "Collection", "detection": ["Clipboard monitoring", "Screen capture detection"]},
    },
    "command_and_control": {
        "T1071": {"name": "Application Layer Protocol", "tactic": "C2", "detection": ["Web proxy logs", "DNS query analysis"]},
        "T1095": {"name": "Non-Application Layer Protocol", "tactic": "C2", "detection": ["Raw socket detection", "ICMP tunneling"]},
        "T1573": {"name": "Encrypted Channel", "tactic": "C2", "detection": ["SSL/TLS certificate anomalies", "JA3 fingerprinting"]},
        "T1102": {"name": "Web Service", "tactic": "C2", "detection": ["API call monitoring", "SaaS application logs"]},
    },
    "exfiltration": {
        "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration", "detection": ["Data size monitoring", "Protocol anomaly detection"]},
        "T1567": {"name": "Exfiltration Over Web Service", "tactic": "Exfiltration", "detection": ["Cloud API monitoring", "Web upload monitoring"]},
        "T1020": {"name": "Automated Exfiltration", "tactic": "Exfiltration", "detection": ["Scheduled transfer detection", "Bulk data movement"]},
        "T1052": {"name": "Exfiltration Over Physical Medium", "tactic": "Exfiltration", "detection": ["USB device monitoring", "Print audit logs"]},
    },
    "impact": {
        "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact", "detection": ["File extension changes", "Ransomware notes", "High file modification rate"]},
        "T1490": {"name": "Inhibit System Recovery", "tactic": "Impact", "detection": ["Backup deletion events", "VSS admin events"]},
        "T1485": {"name": "Data Destruction", "tactic": "Impact", "detection": ["Mass file deletion", "Disk wipe detection"]},
        "T1499": {"name": "Endpoint Denial of Service", "tactic": "Impact", "detection": ["Resource exhaustion monitoring", "Downtime alerts"]},
    },
}

TACTIC_ORDER = [
    "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement",
    "collection", "command_and_control", "exfiltration", "impact"
]


class MitreMapper:
    def __init__(self):
        self._technique_cache: Dict[str, Dict[str, Any]] = {}
        for tactic in MITRE_ATTACK_DATA.values():
            for tid, technique in tactic.items():
                # Cache entries carry their own id: the fuzzy-match path in
                # find_technique returns these dicts directly, and without it
                # map_event fell back to the literal string "UNKNOWN".
                entry = {**technique, "technique_id": tid}
                self._technique_cache.setdefault(tid, entry)
                self._technique_cache.setdefault(technique["name"].lower(), entry)
                self._technique_cache.setdefault(tid.lower(), entry)

    def find_technique(self, event_type: str, raw_data: Optional[str] = None) -> Optional[Dict[str, Any]]:
        event_lower = event_type.lower().replace("_", " ").replace("-", " ")

        keyword_map = {
            "phishing": "T1566", "email": "T1566", "phish": "T1566",
            "powershell": "T1059", "ps1": "T1059", "script": "T1059",
            "credential_dump": "T1003", "lsass": "T1003", "mimikatz": "T1003", "dumping": "T1003",
            "lateral": "T1021", "rdp": "T1021", "winrm": "T1021", "wmi": "T1021",
            "ransomware": "T1486", "encrypt": "T1486", "ransom": "T1486",
            "recon": "T1087", "discovery": "T1087", "enumeration": "T1087",
            "c2": "T1071", "beacon": "T1071", "command_and_control": "T1071",
            "privilege_escalation": "T1068", "privesc": "T1068",
            "persistence": "T1547", "startup": "T1547", "schtask": "T1053", "scheduled_task": "T1053",
            "brute_force": "T1110", "password_spray": "T1110",
            "data_exfil": "T1048", "exfiltration": "T1048", "exfil": "T1048",
            "defense_evasion": "T1562", "disable_av": "T1562", "kill_defender": "T1562",
            "process_injection": "T1055", "inject": "T1055",
            "masquerade": "T1036", "masquerading": "T1036",
            "usb": "T1091", "removable": "T1091",
            "account_manipulation": "T1098", "backdoor_account": "T1098",
            "valid_accounts": "T1078", "compromised_account": "T1078",
            "exploit": "T1190", "vulnerability": "T1190",
            "network_scan": "T1046", "port_scan": "T1046",
            "tool_transfer": "T1570", "dropper": "T1570",
            "data_destruction": "T1485", "wiper": "T1485",
            "inhibit_recovery": "T1490", "delete_backup": "T1490",
            "backup_deletion": "T1490",
        }

        for keyword, tid in keyword_map.items():
            if keyword in event_lower:
                return self._annotate(self.get_technique(tid), KEYWORD_MATCH_CONFIDENCE, "keyword")

        if raw_data:
            raw_lower = raw_data.lower()
            for keyword, tid in keyword_map.items():
                if keyword in raw_lower:
                    return self._annotate(self.get_technique(tid), KEYWORD_MATCH_CONFIDENCE, "keyword")

        best_match = None
        best_ratio = FUZZY_MATCH_THRESHOLD
        for tid, technique in sorted(self._technique_cache.items()):
            if tid.startswith("T"):
                name_lower = technique["name"].lower()
                ratio = SequenceMatcher(None, event_lower, name_lower).ratio()
                if ratio > best_ratio:
                    best_ratio = ratio
                    best_match = technique

        # A fuzzy hit reports its own measured similarity rather than borrowing
        # the confidence of an exact keyword match.
        return self._annotate(best_match, round(best_ratio, 4), "fuzzy_name") if best_match else None

    @staticmethod
    def _annotate(
        technique: Optional[Dict[str, Any]], confidence: float, method: str
    ) -> Optional[Dict[str, Any]]:
        if not technique:
            return None
        return {**technique, "match_confidence": confidence, "match_method": method}

    def get_technique(self, technique_id: str) -> Optional[Dict[str, Any]]:
        for tactic in MITRE_ATTACK_DATA.values():
            if technique_id in tactic:
                result = tactic[technique_id].copy()
                result["technique_id"] = technique_id
                return result
        return None

    def get_all_tactics(self) -> Dict[str, Dict[str, Any]]:
        result = {}
        for tactic_name, techniques in MITRE_ATTACK_DATA.items():
            result[tactic_name] = {tid: info.copy() for tid, info in techniques.items()}
        return result

    def get_techniques_for_tactic(self, tactic: str) -> Dict[str, Any]:
        tactic = tactic.lower().replace(" ", "_").replace("-", "_")
        if tactic in MITRE_ATTACK_DATA:
            return {tid: info.copy() for tid, info in MITRE_ATTACK_DATA[tactic].items()}
        return {}

    def get_technique_chain(self, tactic_steps: List[str]) -> List[Dict[str, Any]]:
        result = []
        for step in tactic_steps:
            technique = self.find_technique(step)
            if technique:
                result.append(technique)
        return result

    def map_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        event_type = event_data.get("event_type", event_data.get("type", ""))
        raw_data = event_data.get("raw", event_data.get("description", ""))
        technique = self.find_technique(event_type, raw_data)
        technique_id = normalize_technique_id((technique or {}).get("technique_id"))

        if not technique or not technique_id:
            # An unresolvable match is an unmapped event. Emitting a sentinel
            # id here poisons every downstream technique-set computation.
            return {
                "mapped": False,
                "technique_id": None,
                "technique_name": None,
                "tactic": None,
                "detection": [],
                "confidence": 0.0,
            }

        return {
            "mapped": True,
            "technique_id": technique_id,
            "technique_name": technique.get("name", "Unknown"),
            "tactic": technique.get("tactic", "Unknown"),
            "detection": technique.get("detection", []),
            "confidence": technique.get("match_confidence", KEYWORD_MATCH_CONFIDENCE),
            "match_method": technique.get("match_method", "keyword"),
        }

    def get_next_likely_techniques(self, current_technique: str) -> List[Dict[str, Any]]:
        current = self.get_technique(current_technique)
        if not current:
            return []

        current_tactic = current.get("tactic", "").lower().replace(" ", "_")
        try:
            current_idx = TACTIC_ORDER.index(current_tactic)
        except ValueError:
            return []

        if current_idx >= len(TACTIC_ORDER) - 1:
            return []

        next_tactic = TACTIC_ORDER[current_idx + 1]
        next_techniques = self.get_techniques_for_tactic(next_tactic)
        return [{"technique_id": tid, "name": info["name"], "tactic": info["tactic"]}
                for tid, info in next_techniques.items()]


mitre_mapper = MitreMapper()
