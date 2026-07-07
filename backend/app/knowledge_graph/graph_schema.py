from typing import Dict, Any, List, Optional
from enum import Enum


class NodeType(str, Enum):
    USER = "User"
    SERVER = "Server"
    ASSET = "Asset"
    APPLICATION = "Application"
    THREAT_ACTOR = "ThreatActor"
    CVE = "CVE"
    MITRE_TECHNIQUE = "MITRETechnique"
    POLICY = "Policy"
    CREDENTIAL = "Credential"
    DEPARTMENT = "Department"
    IOT_DEVICE = "IoTDevice"
    OT_DEVICE = "OTDevice"
    FIREWALL = "Firewall"
    SWITCH = "Switch"
    DATABASE = "Database"
    EMAIL = "Email"
    VPN = "VPN"
    CLOUD_SERVICE = "CloudService"
    IDENTITY = "Identity"
    ROLE = "Role"


class RelationshipType(str, Enum):
    CONNECTED_TO = "CONNECTED_TO"
    USES = "USES"
    OWNS = "OWNS"
    EXPLOITS = "EXPLOITS"
    TARGETS = "TARGETS"
    CAN_REACH = "CAN_REACH"
    DEPENDS_ON = "DEPENDS_ON"
    BELONGS_TO = "BELONGS_TO"
    CONTROLS = "CONTROLS"
    COMMUNICATES_WITH = "COMMUNICATES_WITH"
    RUNS_ON = "RUNS_ON"
    HAS_ACCOUNT = "HAS_ACCOUNT"
    CAN_ACCESS = "CAN_ACCESS"
    MONITORED_BY = "MONITORED_BY"
    PROTECTED_BY = "PROTECTED_BY"


NODE_PROPERTIES: Dict[NodeType, Dict[str, type]] = {
    NodeType.USER: {
        "user_id": str, "username": str, "email": str, "department": str,
        "clearance_level": int, "is_active": bool, "mfa_enabled": bool,
        "failed_login_attempts": int, "last_login": str, "created_at": str
    },
    NodeType.SERVER: {
        "server_id": str, "hostname": str, "ip_address": str, "os": str,
        "os_version": str, "role": str, "cpu_cores": int, "ram_gb": int,
        "disk_gb": int, "patch_level": str, "is_virtualized": bool,
        "last_patched": str, "criticality": str
    },
    NodeType.ASSET: {
        "asset_id": str, "name": str, "asset_type": str, "location": str,
        "department": str, "criticality": str, "value": float,
        "is_encrypted": bool, "backup_status": str, "last_assessment": str
    },
    NodeType.APPLICATION: {
        "app_id": str, "name": str, "version": str, "vendor": str,
        "category": str, "port": int, "protocol": str, "is_web": bool,
        "has_vulnerabilities": bool, "auth_method": str
    },
    NodeType.THREAT_ACTOR: {
        "actor_id": str, "name": str, "sophistication": str,
        "motivation": str, "target_sectors": List[str], "active": bool,
        "first_seen": str, "aliases": List[str], "tools": List[str]
    },
    NodeType.CVE: {
        "cve_id": str, "description": str, "cvss_score": float,
        "severity": str, "attack_vector": str, "complexity": str,
        "affected_software": str, "published_date": str,
        "exploit_available": bool, "patch_available": bool
    },
    NodeType.MITRE_TECHNIQUE: {
        "technique_id": str, "name": str, "tactic": str,
        "description": str, "mitigation": str, "detection": str,
        "platform": List[str], "permissions_required": List[str]
    },
    NodeType.POLICY: {
        "policy_id": str, "name": str, "description": str,
        "category": str, "enforcement_level": str, "last_reviewed": str,
        "compliance_standard": str, "is_active": bool
    },
    NodeType.CREDENTIAL: {
        "credential_id": str, "type": str, "username": str,
        "service": str, "is_compromised": bool, "last_rotated": str,
        "strength": str, "stored_securely": bool
    },
    NodeType.DEPARTMENT: {
        "dept_id": str, "name": str, "budget_code": str,
        "head_count": int, "location": str, "sensitivity": str,
        "has_compliance_requirements": bool
    },
    NodeType.IOT_DEVICE: {
        "device_id": str, "name": str, "device_type": str,
        "ip_address": str, "firmware_version": str, "protocol": str,
        "is_compromised": bool, "last_seen": str, "manufacturer": str,
        "vlan": str
    },
    NodeType.OT_DEVICE: {
        "device_id": str, "name": str, "device_type": str,
        "ip_address": str, "firmware_version": str, "protocol": str,
        "plc_type": str, "critical_process": str, "safety_rating": str,
        "last_maintenance": str
    },
    NodeType.FIREWALL: {
        "firewall_id": str, "name": str, "model": str,
        "ip_address": str, "rules_count": int, "allow_list": List[str],
        "block_list": List[str], "firmware_version": str,
        "has_intrusion_prevention": bool, "last_audit": str
    },
    NodeType.SWITCH: {
        "switch_id": str, "name": str, "model": str,
        "ip_address": str, "vlan_count": int, "port_count": int,
        "managed": bool, "span_port_enabled": bool,
        "firmware_version": str, "last_reboot": str
    },
    NodeType.DATABASE: {
        "db_id": str, "name": str, "db_type": str, "version": str,
        "hostname": str, "port": int, "size_gb": float,
        "has_encryption": bool, "has_backup": bool, "is_replicated": bool
    },
    NodeType.EMAIL: {
        "email_id": str, "address": str, "domain": str,
        "provider": str, "has_phishing_filter": bool,
        "has_dmarc": bool, "has_dkim": bool, "is_compromised": bool
    },
    NodeType.VPN: {
        "vpn_id": str, "name": str, "provider": str,
        "protocol": str, "encryption": str, "ip_range": str,
        "concurrent_users": int, "has_mfa": bool, "last_audit": str
    },
    NodeType.CLOUD_SERVICE: {
        "service_id": str, "name": str, "provider": str,
        "service_type": str, "region": str, "has_encryption": bool,
        "compliance_certified": bool, "publicly_accessible": bool,
        "monthly_cost": float
    },
    NodeType.IDENTITY: {
        "identity_id": str, "name": str, "identity_type": str,
        "provider": str, "is_federated": bool,
        "mfa_status": str, "last_auth": str, "risk_score": float
    },
    NodeType.ROLE: {
        "role_id": str, "name": str, "description": str,
        "privilege_level": str, "is_admin": bool,
        "permissions": List[str], "user_count": int
    },
}

RELATIONSHIP_PROPERTIES: Dict[RelationshipType, Dict[str, type]] = {
    RelationshipType.CONNECTED_TO: {
        "protocol": str, "port": int, "bandwidth": str,
        "encrypted": bool, "last_seen": str
    },
    RelationshipType.USES: {
        "frequency": str, "purpose": str, "since": str
    },
    RelationshipType.OWNS: {
        "ownership_type": str, "since": str
    },
    RelationshipType.EXPLOITS: {
        "technique": str, "vector": str, "success_rate": float,
        "complexity": str, "detected": bool
    },
    RelationshipType.TARGETS: {
        "motivation": str, "method": str, "likelihood": str,
        "impact": str
    },
    RelationshipType.CAN_REACH: {
        "protocol": str, "port": int, "firewall_rule_id": str
    },
    RelationshipType.DEPENDS_ON: {
        "dependency_type": str, "critical": bool
    },
    RelationshipType.BELONGS_TO: {
        "since": str, "role": str
    },
    RelationshipType.CONTROLS: {
        "control_type": str, "effective": bool
    },
    RelationshipType.COMMUNICATES_WITH: {
        "protocol": str, "frequency": str, "data_type": str
    },
    RelationshipType.RUNS_ON: {
        "instance_count": int, "resource_usage": str
    },
    RelationshipType.HAS_ACCOUNT: {
        "account_type": str, "privilege_level": str, "created": str
    },
    RelationshipType.CAN_ACCESS: {
        "access_type": str, "authorized": bool, "last_access": str
    },
    RelationshipType.MONITORED_BY: {
        "monitoring_type": str, "tool": str, "coverage": str
    },
    RelationshipType.PROTECTED_BY: {
        "protection_type": str, "rule_id": str, "active": bool
    },
}


NODE_CYPHER_TEMPLATES = {
    NodeType.USER: """
    CREATE CONSTRAINT user_id_unique IF NOT EXISTS
    FOR (n:User) REQUIRE n.user_id IS UNIQUE
    """,
    NodeType.SERVER: """
    CREATE CONSTRAINT server_id_unique IF NOT EXISTS
    FOR (n:Server) REQUIRE n.server_id IS UNIQUE
    """,
    NodeType.CVE: """
    CREATE CONSTRAINT cve_id_unique IF NOT EXISTS
    FOR (n:CVE) REQUIRE n.cve_id IS UNIQUE
    """,
    NodeType.DEPARTMENT: """
    CREATE CONSTRAINT dept_id_unique IF NOT EXISTS
    FOR (n:Department) REQUIRE n.dept_id IS UNIQUE
    """,
    NodeType.MITRE_TECHNIQUE: """
    CREATE CONSTRAINT technique_id_unique IF NOT EXISTS
    FOR (n:MITRETechnique) REQUIRE n.technique_id IS UNIQUE
    """,
}


INDEX_CYPHER_TEMPLATES = [
    "CREATE INDEX server_ip_idx IF NOT EXISTS FOR (n:Server) ON (n.ip_address)",
    "CREATE INDEX asset_criticality_idx IF NOT EXISTS FOR (n:Asset) ON (n.criticality)",
    "CREATE INDEX cve_severity_idx IF NOT EXISTS FOR (n:CVE) ON (n.severity)",
    "CREATE INDEX user_dept_idx IF NOT EXISTS FOR (n:User) ON (n.department)",
    "CREATE INDEX device_type_idx IF NOT EXISTS FOR (n:IoTDevice) ON (n.device_type)",
    "CREATE INDEX ot_device_type_idx IF NOT EXISTS FOR (n:OTDevice) ON (n.device_type)",
]


VALID_NODE_PAIRS: Dict[RelationshipType, List[tuple]] = {
    RelationshipType.CONNECTED_TO: [
        (NodeType.SERVER, NodeType.SWITCH),
        (NodeType.FIREWALL, NodeType.SWITCH),
        (NodeType.IOT_DEVICE, NodeType.SWITCH),
        (NodeType.OT_DEVICE, NodeType.SWITCH),
        (NodeType.VPN, NodeType.FIREWALL),
    ],
    RelationshipType.USES: [
        (NodeType.USER, NodeType.APPLICATION),
        (NodeType.USER, NodeType.SERVER),
        (NodeType.APPLICATION, NodeType.DATABASE),
        (NodeType.USER, NodeType.VPN),
    ],
    RelationshipType.OWNS: [
        (NodeType.DEPARTMENT, NodeType.ASSET),
        (NodeType.DEPARTMENT, NodeType.SERVER),
        (NodeType.USER, NodeType.ASSET),
    ],
    RelationshipType.EXPLOITS: [
        (NodeType.THREAT_ACTOR, NodeType.CVE),
        (NodeType.THREAT_ACTOR, NodeType.ASSET),
        (NodeType.THREAT_ACTOR, NodeType.APPLICATION),
    ],
    RelationshipType.TARGETS: [
        (NodeType.THREAT_ACTOR, NodeType.DEPARTMENT),
        (NodeType.THREAT_ACTOR, NodeType.ASSET),
        (NodeType.THREAT_ACTOR, NodeType.USER),
        (NodeType.CVE, NodeType.APPLICATION),
        (NodeType.CVE, NodeType.SERVER),
    ],
    RelationshipType.CAN_REACH: [
        (NodeType.SERVER, NodeType.SERVER),
        (NodeType.APPLICATION, NodeType.SERVER),
    ],
    RelationshipType.DEPENDS_ON: [
        (NodeType.APPLICATION, NodeType.DATABASE),
        (NodeType.APPLICATION, NodeType.SERVER),
        (NodeType.SERVER, NodeType.SERVER),
    ],
    RelationshipType.BELONGS_TO: [
        (NodeType.USER, NodeType.DEPARTMENT),
        (NodeType.ASSET, NodeType.DEPARTMENT),
        (NodeType.USER, NodeType.ROLE),
    ],
    RelationshipType.CONTROLS: [
        (NodeType.FIREWALL, NodeType.SWITCH),
        (NodeType.FIREWALL, NodeType.VPN),
        (NodeType.ROLE, NodeType.USER),
    ],
    RelationshipType.COMMUNICATES_WITH: [
        (NodeType.IOT_DEVICE, NodeType.SERVER),
        (NodeType.OT_DEVICE, NodeType.SERVER),
        (NodeType.APPLICATION, NodeType.APPLICATION),
    ],
    RelationshipType.RUNS_ON: [
        (NodeType.APPLICATION, NodeType.SERVER),
        (NodeType.DATABASE, NodeType.SERVER),
    ],
    RelationshipType.HAS_ACCOUNT: [
        (NodeType.USER, NodeType.SERVER),
        (NodeType.USER, NodeType.APPLICATION),
        (NodeType.IDENTITY, NodeType.USER),
    ],
    RelationshipType.CAN_ACCESS: [
        (NodeType.ROLE, NodeType.APPLICATION),
        (NodeType.ROLE, NodeType.SERVER),
        (NodeType.ROLE, NodeType.DATABASE),
    ],
    RelationshipType.MONITORED_BY: [
        (NodeType.SERVER, NodeType.APPLICATION),
        (NodeType.SWITCH, NodeType.APPLICATION),
        (NodeType.FIREWALL, NodeType.APPLICATION),
    ],
    RelationshipType.PROTECTED_BY: [
        (NodeType.SERVER, NodeType.FIREWALL),
        (NodeType.DATABASE, NodeType.FIREWALL),
        (NodeType.APPLICATION, NodeType.FIREWALL),
    ],
}


SCHEMA_DEFINITIONS = {
    "constraints": NODE_CYPHER_TEMPLATES,
    "indexes": INDEX_CYPHER_TEMPLATES,
    "node_types": {nt.value: list(props.keys()) for nt, props in NODE_PROPERTIES.items()},
    "relationship_types": {rt.value: list(props.keys()) for rt, props in RELATIONSHIP_PROPERTIES.items()},
    "valid_pairs": {
        rt.value: [(s.value, e.value) for s, e in pairs]
        for rt, pairs in VALID_NODE_PAIRS.items()
    },
}


def get_node_properties(node_type: NodeType) -> Dict[str, type]:
    return NODE_PROPERTIES.get(node_type, {})


def get_relationship_properties(rel_type: RelationshipType) -> Dict[str, type]:
    return RELATIONSHIP_PROPERTIES.get(rel_type, {})


def validate_node_type(label: str) -> bool:
    return label in [nt.value for nt in NodeType]


def validate_relationship_type(rel_type: str) -> bool:
    return rel_type in [rt.value for rt in RelationshipType]
