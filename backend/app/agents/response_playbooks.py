from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta
from enum import Enum


class RiskLevel(Enum):
    GREEN = "green"
    YELLOW = "yellow"
    ORANGE = "orange"
    RED = "red"


class ApprovalLevel(Enum):
    NONE = "none"
    NOTIFY = "notify"
    ASK_APPROVAL = "ask_approval"
    IMMEDIATE = "immediate"


class PlaybookStep:
    def __init__(
        self,
        order: int,
        action: str,
        description: str,
        command: str,
        requires_rollback: bool = False,
        rollback_command: Optional[str] = None,
        timeout_seconds: int = 30
    ):
        self.order = order
        self.action = action
        self.description = description
        self.command = command
        self.requires_rollback = requires_rollback
        self.rollback_command = rollback_command
        self.timeout_seconds = timeout_seconds

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "order": self.order,
            "action": self.action,
            "description": self.description,
            "command": self.command,
            "timeout_seconds": self.timeout_seconds,
        }
        if self.requires_rollback:
            result["rollback_command"] = self.rollback_command
        return result


class Playbook:
    def __init__(
        self,
        name: str,
        description: str,
        risk_level: RiskLevel,
        approval_level: ApprovalLevel,
        owner_team: str,
        steps: List[PlaybookStep],
        prerequisites: Optional[List[str]] = None,
        applicable_os: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        version: str = "1.0.0"
    ):
        self.name = name
        self.description = description
        self.risk_level = risk_level
        self.approval_level = approval_level
        self.owner_team = owner_team
        self.steps = sorted(steps, key=lambda s: s.order)
        self.prerequisites = prerequisites or []
        self.applicable_os = applicable_os or ["windows", "linux", "macos"]
        self.tags = tags or []
        self.version = version
        self.created_at = datetime.utcnow()
        self.updated_at = datetime.utcnow()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level.value,
            "approval_level": self.approval_level.value,
            "owner_team": self.owner_team,
            "steps": [s.to_dict() for s in self.steps],
            "prerequisites": self.prerequisites,
            "applicable_os": self.applicable_os,
            "tags": self.tags,
            "version": self.version,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }


PLAYBOOK_REGISTRY: Dict[str, Playbook] = {}


def register_playbook(playbook: Playbook):
    PLAYBOOK_REGISTRY[playbook.name] = playbook


def get_playbook(name: str) -> Optional[Playbook]:
    return PLAYBOOK_REGISTRY.get(name)


def get_playbooks_by_risk(risk: RiskLevel) -> List[Playbook]:
    return [p for p in PLAYBOOK_REGISTRY.values() if p.risk_level == risk]


def get_playbooks_by_tag(tag: str) -> List[Playbook]:
    return [p for p in PLAYBOOK_REGISTRY.values() if tag in p.tags]


def list_playbooks() -> List[Dict[str, Any]]:
    return [p.to_dict() for p in PLAYBOOK_REGISTRY.values()]


block_ip_steps = [
    PlaybookStep(1, "identify_source", "Identify the source IP to block", "get_source_ip", requires_rollback=False),
    PlaybookStep(2, "validate_ip", "Validate IP is not a critical system", "check_ip_criticality", requires_rollback=False),
    PlaybookStep(3, "block_firewall", "Block IP on network firewall", "firewall block {ip}", requires_rollback=True, rollback_command="firewall unblock {ip}"),
    PlaybookStep(4, "block_waf", "Block IP on WAF", "waf block {ip}", requires_rollback=True, rollback_command="waf unblock {ip}"),
    PlaybookStep(5, "update_ioc_list", "Add IP to IOC list", "ioc add {ip}"),
    PlaybookStep(6, "notify_soc", "Notify SOC team of blocking action", "soc notify block_ip {ip}"),
]
block_ip_playbook = Playbook(
    name="block_ip",
    description="Block a malicious IP address across network perimeters",
    risk_level=RiskLevel.ORANGE,
    approval_level=ApprovalLevel.ASK_APPROVAL,
    owner_team="network_security",
    steps=block_ip_steps,
    prerequisites=["firewall_access", "waf_access"],
    tags=["network", "ip_block", "containment"],
)

disable_account_steps = [
    PlaybookStep(1, "identify_account", "Identify the account to disable", "get_account_info {user}"),
    PlaybookStep(2, "check_privilege", "Check if account is a privileged/emergency account", "check_account_privilege {user}"),
    PlaybookStep(3, "disable_ad", "Disable account in Active Directory", "ad disable {user}", requires_rollback=True, rollback_command="ad enable {user}"),
    PlaybookStep(4, "revoke_sessions", "Revoke all active sessions", "revoke_sessions {user}", requires_rollback=False),
    PlaybookStep(5, "reset_password", "Reset account password", "ad reset_password {user}", requires_rollback=True, rollback_command="ad set_password {user} {old_hash}"),
    PlaybookStep(6, "notify_hr", "Notify HR and manager", "soc notify account_disabled {user}"),
]
disable_account_playbook = Playbook(
    name="disable_account",
    description="Disable a compromised user account",
    risk_level=RiskLevel.ORANGE,
    approval_level=ApprovalLevel.ASK_APPROVAL,
    owner_team="identity_team",
    steps=disable_account_steps,
    prerequisites=["ad_admin"],
    tags=["identity", "account", "containment"],
)

kill_process_steps = [
    PlaybookStep(1, "identify_process", "Identify the malicious process", "get_process_info {pid}"),
    PlaybookStep(2, "validate_process", "Validate process is not system-critical", "check_process_criticality {pid}"),
    PlaybookStep(3, "kill_process", "Terminate the process", "os kill {pid}", requires_rollback=True, rollback_command="os start {process_path}"),
    PlaybookStep(4, "remove_persistence", "Remove any persistence mechanisms", "os remove_persistence {pid}"),
    PlaybookStep(5, "scan_related", "Scan for related malicious processes", "os scan_related {pid}"),
]
kill_process_playbook = Playbook(
    name="kill_process",
    description="Terminate a malicious process on an endpoint",
    risk_level=RiskLevel.YELLOW,
    approval_level=ApprovalLevel.NOTIFY,
    owner_team="endpoint_security",
    steps=kill_process_steps,
    prerequisites=["endpoint_admin"],
    tags=["endpoint", "process", "containment"],
)

snapshot_vm_steps = [
    PlaybookStep(1, "identify_vm", "Identify the VM to snapshot", "get_vm_info {vm_id}"),
    PlaybookStep(2, "quiesce_vm", "Quiesce the VM for consistent snapshot", "vm quiesce {vm_id}", requires_rollback=True, rollback_command="vm unquiesce {vm_id}"),
    PlaybookStep(3, "create_snapshot", "Create forensic snapshot", "vm snapshot {vm_id} --name forensic_{timestamp}", requires_rollback=True, rollback_command="vm delete_snapshot {vm_id} forensic_{timestamp}"),
    PlaybookStep(4, "isolate_vm", "Isolate VM from network while preserving snapshot", "vm isolate {vm_id}", requires_rollback=True, rollback_command="vm connect {vm_id}"),
    PlaybookStep(5, "notify_forensics", "Notify forensics team of available snapshot", "soc notify snapshot {vm_id}"),
]
snapshot_vm_playbook = Playbook(
    name="snapshot_vm",
    description="Create a forensic snapshot of a compromised VM before remediation",
    risk_level=RiskLevel.YELLOW,
    approval_level=ApprovalLevel.ASK_APPROVAL,
    owner_team="infrastructure_team",
    steps=snapshot_vm_steps,
    prerequisites=["hypervisor_admin"],
    tags=["vm", "forensics", "snapshot"],
)

quarantine_host_steps = [
    PlaybookStep(1, "identify_host", "Identify the host to quarantine", "get_host_info {host_id}"),
    PlaybookStep(2, "check_critical_role", "Check if host has critical role (DC, SQL, OT)", "check_host_role {host_id}"),
    PlaybookStep(3, "network_isolation", "Isolate host on network (VLAN isolation)", "network isolate {host_id}", requires_rollback=True, rollback_command="network restore {host_id}"),
    PlaybookStep(4, "block_dns", "Block DNS resolution for host", "dns block {hostname}", requires_rollback=True, rollback_command="dns allow {hostname}"),
    PlaybookStep(5, "alert_users", "Notify active users of quarantine", "os notify_users {host_id} 'Host quarantined for security investigation'"),
]
quarantine_host_playbook = Playbook(
    name="quarantine_host",
    description="Isolate a compromised host from the network",
    risk_level=RiskLevel.RED,
    approval_level=ApprovalLevel.IMMEDIATE,
    owner_team="incident_response",
    steps=quarantine_host_steps,
    prerequisites=["network_admin", "dns_admin"],
    tags=["host", "quarantine", "containment", "isolation"],
)

rotate_credentials_steps = [
    PlaybookStep(1, "identify_credential", "Identify the credential to rotate", "get_credential_info {credential_id}"),
    PlaybookStep(2, "check_service_impact", "Check services dependent on this credential", "check_credential_dependencies {credential_id}"),
    PlaybookStep(3, "rotate_password", "Rotate the password/secret", "vault rotate {credential_id}", requires_rollback=True, rollback_command="vault restore {credential_id} {old_version}"),
    PlaybookStep(4, "update_services", "Update dependent services with new credential", "update_dependent_services {credential_id}"),
    PlaybookStep(5, "verify_access", "Verify services work with new credential", "verify_service_access {credential_id}"),
]
rotate_credentials_playbook = Playbook(
    name="rotate_credentials",
    description="Rotate compromised credentials across all dependent services",
    risk_level=RiskLevel.ORANGE,
    approval_level=ApprovalLevel.ASK_APPROVAL,
    owner_team="identity_team",
    steps=rotate_credentials_steps,
    prerequisites=["vault_admin"],
    tags=["credentials", "rotation", "remediation"],
)

network_isolation_steps = [
    PlaybookStep(1, "identify_segment", "Identify the network segment to isolate", "get_segment_info {segment_id}"),
    PlaybookStep(2, "check_critical_services", "Identify critical services in segment", "check_segment_services {segment_id}"),
    PlaybookStep(3, "apply_acl", "Apply strict ACL to segment boundaries", "network apply_acl {segment_id} --deny-all", requires_rollback=True, rollback_command="network remove_acl {segment_id}"),
    PlaybookStep(4, "enable_audit", "Enable full audit logging on segment", "network enable_audit {segment_id}"),
    PlaybookStep(5, "notify_business", "Notify business owners of isolation", "soc notify isolation {segment_id}"),
]
network_isolation_playbook = Playbook(
    name="network_isolation",
    description="Isolate an entire network segment to contain lateral movement",
    risk_level=RiskLevel.RED,
    approval_level=ApprovalLevel.IMMEDIATE,
    owner_team="network_security",
    steps=network_isolation_steps,
    prerequisites=["network_admin", "soc_access"],
    tags=["network", "isolation", "containment", "lateral_movement"],
)

notify_soc_steps = [
    PlaybookStep(1, "gather_evidence", "Gather all relevant evidence and context", "gather_alert_evidence {alert_id}"),
    PlaybookStep(2, "create_ticket", "Create SOC ticket with evidence", "soc create_ticket --priority {priority} --evidence {evidence}"),
    PlaybookStep(3, "escalate_if_critical", "Escalate to senior analyst if critical severity", "soc escalate {ticket_id} {severity}"),
    PlaybookStep(4, "update_metrics", "Update incident response metrics", "metrics record_alert {alert_id}"),
]
notify_soc_playbook = Playbook(
    name="notify_soc",
    description="Create and escalate a SOC ticket with evidence",
    risk_level=RiskLevel.GREEN,
    approval_level=ApprovalLevel.NOTIFY,
    owner_team="soc",
    steps=notify_soc_steps,
    tags=["notification", "soc", "ticketing"],
)

for _p in [
    block_ip_playbook,
    disable_account_playbook,
    kill_process_playbook,
    snapshot_vm_playbook,
    quarantine_host_playbook,
    rotate_credentials_playbook,
    network_isolation_playbook,
    notify_soc_playbook,
]:
    register_playbook(_p)
