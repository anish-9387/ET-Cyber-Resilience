from typing import Dict, Any, List, Optional
from app.knowledge_graph.graph_manager import graph_manager
from app.knowledge_graph.graph_schema import NodeType, RelationshipType
from app.core.logger import logger


SEED_DATA = {
    "departments": [
        {"dept_id": "dept-001", "name": "Emergency Medicine", "budget_code": "EM-2024",
         "head_count": 45, "location": "Wing A, Floor 1", "sensitivity": "high",
         "has_compliance_requirements": True},
        {"dept_id": "dept-002", "name": "Radiology", "budget_code": "RAD-2024",
         "head_count": 30, "location": "Wing B, Floor 2", "sensitivity": "high",
         "has_compliance_requirements": True},
        {"dept_id": "dept-003", "name": "IT Operations", "budget_code": "IT-2024",
         "head_count": 25, "location": "Basement, Server Room", "sensitivity": "critical",
         "has_compliance_requirements": False},
        {"dept_id": "dept-004", "name": "Administration", "budget_code": "ADMIN-2024",
         "head_count": 60, "location": "Wing C, Floor 3", "sensitivity": "medium",
         "has_compliance_requirements": True},
        {"dept_id": "dept-005", "name": "Pharmacy", "budget_code": "PHARM-2024",
         "head_count": 20, "location": "Wing A, Floor 2", "sensitivity": "high",
         "has_compliance_requirements": True},
        {"dept_id": "dept-006", "name": "Cardiology", "budget_code": "CARD-2024",
         "head_count": 35, "location": "Wing B, Floor 1", "sensitivity": "high",
         "has_compliance_requirements": True},
    ],
    "users": [
        {"user_id": "user-001", "username": "jdoe", "email": "jdoe@hospital.gov",
         "department": "Emergency Medicine", "clearance_level": 3, "is_active": True,
         "mfa_enabled": False, "failed_login_attempts": 0,
         "last_login": "2024-11-15T08:30:00Z", "created_at": "2020-03-10T00:00:00Z"},
        {"user_id": "user-002", "username": "asmith", "email": "asmith@hospital.gov",
         "department": "Radiology", "clearance_level": 4, "is_active": True,
         "mfa_enabled": True, "failed_login_attempts": 0,
         "last_login": "2024-11-15T09:15:00Z", "created_at": "2019-07-22T00:00:00Z"},
        {"user_id": "user-003", "username": "admin_mike", "email": "mike.chen@hospital.gov",
         "department": "IT Operations", "clearance_level": 5, "is_active": True,
         "mfa_enabled": True, "failed_login_attempts": 1,
         "last_login": "2024-11-15T07:45:00Z", "created_at": "2018-01-15T00:00:00Z"},
        {"user_id": "user-004", "username": "linda.ross", "email": "lross@hospital.gov",
         "department": "Administration", "clearance_level": 4, "is_active": True,
         "mfa_enabled": False, "failed_login_attempts": 3,
         "last_login": "2024-11-14T16:20:00Z", "created_at": "2020-06-01T00:00:00Z"},
        {"user_id": "user-005", "username": "dr.williams", "email": "bwilliams@hospital.gov",
         "department": "Cardiology", "clearance_level": 4, "is_active": True,
         "mfa_enabled": False, "failed_login_attempts": 0,
         "last_login": "2024-11-15T10:00:00Z", "created_at": "2021-02-14T00:00:00Z"},
        {"user_id": "user-006", "username": "nurse_johnson", "email": "kjohnson@hospital.gov",
         "department": "Emergency Medicine", "clearance_level": 2, "is_active": True,
         "mfa_enabled": False, "failed_login_attempts": 2,
         "last_login": "2024-11-14T22:10:00Z", "created_at": "2022-09-05T00:00:00Z"},
        {"user_id": "user-007", "username": "tech_ray", "email": "ray.kim@hospital.gov",
         "department": "IT Operations", "clearance_level": 4, "is_active": True,
         "mfa_enabled": True, "failed_login_attempts": 0,
         "last_login": "2024-11-15T06:55:00Z", "created_at": "2021-11-30T00:00:00Z"},
        {"user_id": "user-008", "username": "pharma.lee", "email": "slee@hospital.gov",
         "department": "Pharmacy", "clearance_level": 3, "is_active": True,
         "mfa_enabled": False, "failed_login_attempts": 0,
         "last_login": "2024-11-15T08:00:00Z", "created_at": "2023-04-18T00:00:00Z"},
    ],
    "servers": [
        {"server_id": "srv-001", "hostname": "DC01", "ip_address": "10.0.1.10",
         "os": "Windows Server 2022", "os_version": "21H2", "role": "Domain Controller",
         "cpu_cores": 8, "ram_gb": 64, "disk_gb": 2000, "patch_level": "KB5020044",
         "is_virtualized": True, "last_patched": "2024-10-15", "criticality": "critical"},
        {"server_id": "srv-002", "hostname": "FILESRV01", "ip_address": "10.0.1.20",
         "os": "Windows Server 2022", "os_version": "21H2", "role": "File Server",
         "cpu_cores": 4, "ram_gb": 32, "disk_gb": 8000, "patch_level": "KB5020044",
         "is_virtualized": True, "last_patched": "2024-10-10", "criticality": "high"},
        {"server_id": "srv-003", "hostname": "DBSRV01", "ip_address": "10.0.2.10",
         "os": "Ubuntu 22.04 LTS", "os_version": "22.04", "role": "Database Server",
         "cpu_cores": 16, "ram_gb": 128, "disk_gb": 4000, "patch_level": "5.15.0-1054",
         "is_virtualized": False, "last_patched": "2024-11-01", "criticality": "critical"},
        {"server_id": "srv-004", "hostname": "EHRSRV01", "ip_address": "10.0.3.10",
         "os": "Windows Server 2022", "os_version": "21H2", "role": "Application Server",
         "cpu_cores": 8, "ram_gb": 64, "disk_gb": 1000, "patch_level": "KB5020044",
         "is_virtualized": True, "last_patched": "2024-09-20", "criticality": "critical"},
        {"server_id": "srv-005", "hostname": "MAILSRV01", "ip_address": "10.0.1.30",
         "os": "Windows Server 2022", "os_version": "21H2", "role": "Mail Server",
         "cpu_cores": 4, "ram_gb": 16, "disk_gb": 500, "patch_level": "KB5018421",
         "is_virtualized": True, "last_patched": "2024-08-15", "criticality": "high"},
        {"server_id": "srv-006", "hostname": "BACKUPSRV01", "ip_address": "10.0.4.10",
         "os": "Ubuntu 22.04 LTS", "os_version": "22.04", "role": "Backup Server",
         "cpu_cores": 8, "ram_gb": 32, "disk_gb": 12000, "patch_level": "5.15.0-1054",
         "is_virtualized": False, "last_patched": "2024-11-05", "criticality": "high"},
        {"server_id": "srv-007", "hostname": "WEBSRV01", "ip_address": "10.0.3.20",
         "os": "Ubuntu 22.04 LTS", "os_version": "22.04", "role": "Web Server",
         "cpu_cores": 4, "ram_gb": 16, "disk_gb": 250, "patch_level": "5.15.0-1054",
         "is_virtualized": True, "last_patched": "2024-10-28", "criticality": "medium"},
    ],
    "databases": [
        {"db_id": "db-001", "name": "EHR_PRODUCTION", "db_type": "PostgreSQL",
         "version": "15.4", "hostname": "DBSRV01", "port": 5432, "size_gb": 2500.0,
         "has_encryption": True, "has_backup": True, "is_replicated": True},
        {"db_id": "db-002", "name": "PACS_ARCHIVE", "db_type": "PostgreSQL",
         "version": "15.2", "hostname": "DBSRV01", "port": 5433, "size_gb": 8000.0,
         "has_encryption": True, "has_backup": True, "is_replicated": True},
        {"db_id": "db-003", "name": "ACTIVE_DIRECTORY", "db_type": "Microsoft SQL Server",
         "version": "2019", "hostname": "DC01", "port": 1433, "size_gb": 50.0,
         "has_encryption": True, "has_backup": True, "is_replicated": True},
    ],
    "applications": [
        {"app_id": "app-001", "name": "Electronic Health Records", "version": "6.2.1",
         "vendor": "MediTech", "category": "Healthcare", "port": 443, "protocol": "HTTPS",
         "is_web": True, "has_vulnerabilities": True, "auth_method": "SAML"},
        {"app_id": "app-002", "name": "PACS", "version": "4.8.0",
         "vendor": "GE Healthcare", "category": "Medical Imaging", "port": 8443,
         "protocol": "HTTPS", "is_web": True, "has_vulnerabilities": False,
         "auth_method": "LDAP"},
        {"app_id": "app-003", "name": "Microsoft Exchange", "version": "2022",
         "vendor": "Microsoft", "category": "Email", "port": 443, "protocol": "HTTPS",
         "is_web": True, "has_vulnerabilities": True, "auth_method": "OAuth"},
        {"app_id": "app-004", "name": "Splunk SIEM", "version": "9.1.0",
         "vendor": "Splunk", "category": "Security", "port": 8089, "protocol": "HTTPS",
         "is_web": True, "has_vulnerabilities": False, "auth_method": "SAML"},
        {"app_id": "app-005", "name": "Hospital Pharmacy System", "version": "3.4.2",
         "vendor": "RXConnect", "category": "Healthcare", "port": 443, "protocol": "HTTPS",
         "is_web": True, "has_vulnerabilities": True, "auth_method": "LDAP"},
    ],
    "iot_devices": [
        {"device_id": "iot-001", "name": "MRI-01", "device_type": "MRI Scanner",
         "ip_address": "10.0.10.10", "firmware_version": "3.2.1", "protocol": "DICOM",
         "is_compromised": False, "last_seen": "2024-11-15T10:30:00Z",
         "manufacturer": "Siemens", "vlan": "MEDICAL_DEVICES"},
        {"device_id": "iot-002", "name": "CT-01", "device_type": "CT Scanner",
         "ip_address": "10.0.10.20", "firmware_version": "2.8.4", "protocol": "DICOM",
         "is_compromised": False, "last_seen": "2024-11-15T10:15:00Z",
         "manufacturer": "GE Healthcare", "vlan": "MEDICAL_DEVICES"},
        {"device_id": "iot-003", "name": "XRAY-01", "device_type": "X-Ray Machine",
         "ip_address": "10.0.10.30", "firmware_version": "1.9.2", "protocol": "DICOM",
         "is_compromised": False, "last_seen": "2024-11-15T09:45:00Z",
         "manufacturer": "Philips", "vlan": "MEDICAL_DEVICES"},
        {"device_id": "iot-004", "name": "INFUSION-PUMP-01", "device_type": "Infusion Pump",
         "ip_address": "10.0.11.10", "firmware_version": "5.0.1", "protocol": "HL7",
         "is_compromised": False, "last_seen": "2024-11-15T10:00:00Z",
         "manufacturer": "Baxter", "vlan": "PATIENT_MONITORING"},
        {"device_id": "iot-005", "name": "HEART-MONITOR-01", "device_type": "Heart Monitor",
         "ip_address": "10.0.11.20", "firmware_version": "4.3.0", "protocol": "HL7",
         "is_compromised": False, "last_seen": "2024-11-15T10:28:00Z",
         "manufacturer": "Medtronic", "vlan": "PATIENT_MONITORING"},
    ],
    "network_devices": {
        "firewalls": [
            {"firewall_id": "fw-001", "name": "FW-CORE", "model": "Palo Alto PA-5250",
             "ip_address": "10.0.0.1", "rules_count": 150, "allow_list": ["10.0.0.0/8"],
             "block_list": ["0.0.0.0/0"], "firmware_version": "11.1.2",
             "has_intrusion_prevention": True, "last_audit": "2024-10-01"},
            {"firewall_id": "fw-002", "name": "FW-DMZ", "model": "Palo Alto PA-440",
             "ip_address": "10.0.0.2", "rules_count": 45, "allow_list": ["10.0.3.0/24"],
             "block_list": ["0.0.0.0/0"], "firmware_version": "11.1.1",
             "has_intrusion_prevention": True, "last_audit": "2024-09-15"},
        ],
        "switches": [
            {"switch_id": "sw-001", "name": "SW-CORE-01", "model": "Cisco Catalyst 9500",
             "ip_address": "10.0.0.10", "vlan_count": 15, "port_count": 48,
             "managed": True, "span_port_enabled": True, "firmware_version": "17.9.1",
             "last_reboot": "2024-10-20"},
            {"switch_id": "sw-002", "name": "SW-CORE-02", "model": "Cisco Catalyst 9500",
             "ip_address": "10.0.0.11", "vlan_count": 15, "port_count": 48,
             "managed": True, "span_port_enabled": True, "firmware_version": "17.9.1",
             "last_reboot": "2024-10-20"},
            {"switch_id": "sw-003", "name": "SW-DMZ", "model": "Cisco Catalyst 9300",
             "ip_address": "10.0.3.1", "vlan_count": 5, "port_count": 24,
             "managed": True, "span_port_enabled": False, "firmware_version": "17.6.3",
             "last_reboot": "2024-11-01"},
        ],
    },
    "vpn": [
        {"vpn_id": "vpn-001", "name": "Hospital VPN", "provider": "OpenVPN",
         "protocol": "OpenVPN", "encryption": "AES-256-GCM", "ip_range": "10.255.0.0/24",
         "concurrent_users": 100, "has_mfa": True, "last_audit": "2024-10-15"},
    ],
    "roles": [
        {"role_id": "role-001", "name": "System Administrator", "description": "Full system access",
         "privilege_level": "critical", "is_admin": True,
         "permissions": ["admin:all", "network:configure", "users:manage"], "user_count": 2},
        {"role_id": "role-002", "name": "Physician", "description": "Medical staff access",
         "privilege_level": "high", "is_admin": False,
         "permissions": ["ehr:read", "ehr:write", "pacs:read", "pharmacy:prescribe"],
         "user_count": 45},
        {"role_id": "role-003", "name": "Nurse", "description": "Nursing staff access",
         "privilege_level": "medium", "is_admin": False,
         "permissions": ["ehr:read", "ehr:write", "pacs:read"], "user_count": 120},
        {"role_id": "role-004", "name": "Radiologist", "description": "Radiology department access",
         "privilege_level": "high", "is_admin": False,
         "permissions": ["ehr:read", "pacs:read", "pacs:write", "pacs:admin"],
         "user_count": 8},
        {"role_id": "role-005", "name": "IT Support", "description": "IT helpdesk access",
         "privilege_level": "medium", "is_admin": False,
         "permissions": ["network:monitor", "servers:reboot", "tickets:manage"],
         "user_count": 10},
    ],
    "identities": [
        {"identity_id": "id-001", "name": "Azure AD Sync", "identity_type": "Service Principal",
         "provider": "Azure AD", "is_federated": True, "mfa_status": "enabled",
         "last_auth": "2024-11-15T10:25:00Z", "risk_score": 5.0},
        {"identity_id": "id-002", "name": "Okta SSO", "identity_type": "Federated Identity",
         "provider": "Okta", "is_federated": True, "mfa_status": "enabled",
         "last_auth": "2024-11-15T10:20:00Z", "risk_score": 3.0},
    ],
    "cloud_services": [
        {"service_id": "cs-001", "name": "AWS S3 Backup", "provider": "AWS",
         "service_type": "Storage", "region": "us-east-1", "has_encryption": True,
         "compliance_certified": True, "publicly_accessible": False, "monthly_cost": 4500.0},
        {"service_id": "cs-002", "name": "Azure AD", "provider": "Azure",
         "service_type": "Identity", "region": "us-east", "has_encryption": True,
         "compliance_certified": True, "publicly_accessible": False, "monthly_cost": 0.0},
    ],
    "policies": [
        {"policy_id": "pol-001", "name": "HIPAA Access Control", "description": "Healthcare data access policy",
         "category": "Compliance", "enforcement_level": "strict", "last_reviewed": "2024-09-01",
         "compliance_standard": "HIPAA", "is_active": True},
        {"policy_id": "pol-002", "name": "Password Policy", "description": "Password complexity requirements",
         "category": "Security", "enforcement_level": "moderate", "last_reviewed": "2024-08-15",
         "compliance_standard": "NIST 800-53", "is_active": True},
        {"policy_id": "pol-003", "name": "Network Segmentation", "description": "VLAN and firewall rules",
         "category": "Network", "enforcement_level": "strict", "last_reviewed": "2024-10-01",
         "compliance_standard": "NIST CSF", "is_active": True},
    ],
}


async def create_constraints_and_indexes():
    from app.knowledge_graph.graph_schema import NODE_CYPHER_TEMPLATES, INDEX_CYPHER_TEMPLATES
    async with graph_manager.driver.session() as session:
        for cypher in NODE_CYPHER_TEMPLATES.values():
            await session.run(cypher)
        for cypher in INDEX_CYPHER_TEMPLATES:
            await session.run(cypher)
    logger.info("Constraints and indexes created")


async def populate_seed_data():
    stored_ids = {}

    dept_ids = {}
    for dept in SEED_DATA["departments"]:
        node_id = await graph_manager.create_node([NodeType.DEPARTMENT.value], dept)
        dept_ids[dept["dept_id"]] = node_id
    stored_ids["departments"] = dept_ids

    user_ids = {}
    for user in SEED_DATA["users"]:
        node_id = await graph_manager.create_node([NodeType.USER.value], user)
        user_ids[user["user_id"]] = node_id
    stored_ids["users"] = user_ids

    server_ids = {}
    for srv in SEED_DATA["servers"]:
        node_id = await graph_manager.create_node([NodeType.SERVER.value], srv)
        server_ids[srv["server_id"]] = node_id
    stored_ids["servers"] = server_ids

    db_ids = {}
    for db in SEED_DATA["databases"]:
        node_id = await graph_manager.create_node([NodeType.DATABASE.value], db)
        db_ids[db["db_id"]] = node_id
    stored_ids["databases"] = db_ids

    app_ids = {}
    for app in SEED_DATA["applications"]:
        node_id = await graph_manager.create_node([NodeType.APPLICATION.value], app)
        app_ids[app["app_id"]] = node_id
    stored_ids["applications"] = app_ids

    iot_ids = {}
    for device in SEED_DATA["iot_devices"]:
        node_id = await graph_manager.create_node([NodeType.IOT_DEVICE.value], device)
        iot_ids[device["device_id"]] = node_id
    stored_ids["iot_devices"] = iot_ids

    fw_ids = {}
    for fw in SEED_DATA["network_devices"]["firewalls"]:
        node_id = await graph_manager.create_node([NodeType.FIREWALL.value], fw)
        fw_ids[fw["firewall_id"]] = node_id
    stored_ids["firewalls"] = fw_ids

    sw_ids = {}
    for sw in SEED_DATA["network_devices"]["switches"]:
        node_id = await graph_manager.create_node([NodeType.SWITCH.value], sw)
        sw_ids[sw["switch_id"]] = node_id
    stored_ids["switches"] = sw_ids

    vpn_ids = {}
    for vpn in SEED_DATA["vpn"]:
        node_id = await graph_manager.create_node([NodeType.VPN.value], vpn)
        vpn_ids[vpn["vpn_id"]] = node_id
    stored_ids["vpn"] = vpn_ids

    cred_ids = {}
    credentials = [
        {"credential_id": "cred-001", "type": "password", "username": "svc_ehr",
         "service": "EHR System", "is_compromised": False, "last_rotated": "2024-06-01",
         "strength": "strong", "stored_securely": True},
        {"credential_id": "cred-002", "type": "password", "username": "backup_admin",
         "service": "Backup Server", "is_compromised": False, "last_rotated": "2024-01-15",
         "strength": "weak", "stored_securely": False},
        {"credential_id": "cred-003", "type": "ssh_key", "username": "root",
         "service": "DBSRV01", "is_compromised": True, "last_rotated": "2023-11-20",
         "strength": "strong", "stored_securely": False},
    ]
    for cred in credentials:
        node_id = await graph_manager.create_node([NodeType.CREDENTIAL.value], cred)
        cred_ids[cred["credential_id"]] = node_id
    stored_ids["credentials"] = cred_ids

    role_ids = {}
    for role in SEED_DATA["roles"]:
        node_id = await graph_manager.create_node([NodeType.ROLE.value], role)
        role_ids[role["role_id"]] = node_id
    stored_ids["roles"] = role_ids

    identity_ids = {}
    for identity in SEED_DATA["identities"]:
        node_id = await graph_manager.create_node([NodeType.IDENTITY.value], identity)
        identity_ids[identity["identity_id"]] = node_id
    stored_ids["identities"] = identity_ids

    cs_ids = {}
    for cs in SEED_DATA["cloud_services"]:
        node_id = await graph_manager.create_node([NodeType.CLOUD_SERVICE.value], cs)
        cs_ids[cs["service_id"]] = node_id
    stored_ids["cloud_services"] = cs_ids

    policy_ids = {}
    for pol in SEED_DATA["policies"]:
        node_id = await graph_manager.create_node([NodeType.POLICY.value], pol)
        policy_ids[pol["policy_id"]] = node_id
    stored_ids["policies"] = policy_ids

    threat_actor_ids = {}
    threat_actors = [
        {"actor_id": "ta-001", "name": "APT-C-23", "sophistication": "high",
         "motivation": "espionage", "target_sectors": ["Healthcare", "Government"],
         "active": True, "first_seen": "2023-06-15", "aliases": ["Gaza Cybergang"],
         "tools": ["Micropsia", "PyMicropsia"]},
        {"actor_id": "ta-002", "name": "LockBit Ransomware", "sophistication": "high",
         "motivation": "financial", "target_sectors": ["Healthcare", "Education", "Government"],
         "active": True, "first_seen": "2022-01-01", "aliases": ["LockBit 3.0"],
         "tools": ["StealBit", "LockBit勒索软件"]},
    ]
    for ta in threat_actors:
        node_id = await graph_manager.create_node([NodeType.THREAT_ACTOR.value], ta)
        threat_actor_ids[ta["actor_id"]] = node_id
    stored_ids["threat_actors"] = threat_actor_ids

    cve_ids = {}
    cves = [
        {"cve_id": "CVE-2024-001", "description": "EHR System SQL Injection",
         "cvss_score": 9.1, "severity": "critical", "attack_vector": "network",
         "complexity": "low", "affected_software": "MediTech EHR 6.2.1",
         "published_date": "2024-03-15", "exploit_available": True,
         "patch_available": True},
        {"cve_id": "CVE-2024-002", "description": "Exchange Server Privilege Escalation",
         "cvss_score": 8.8, "severity": "high", "attack_vector": "network",
         "complexity": "low", "affected_software": "Microsoft Exchange 2022",
         "published_date": "2024-04-10", "exploit_available": True,
         "patch_available": True},
        {"cve_id": "CVE-2024-003", "description": "DICOM Protocol Buffer Overflow",
         "cvss_score": 7.5, "severity": "high", "attack_vector": "adjacent_network",
         "complexity": "medium", "affected_software": "Siemens MRI Firmware 3.2.1",
         "published_date": "2024-05-01", "exploit_available": True,
         "patch_available": False},
        {"cve_id": "CVE-2024-004", "description": "Palo Alto PAN-OS RCE",
         "cvss_score": 9.8, "severity": "critical", "attack_vector": "network",
         "complexity": "low", "affected_software": "PAN-OS 11.1.x",
         "published_date": "2024-02-20", "exploit_available": True,
         "patch_available": False},
    ]
    for cve in cves:
        node_id = await graph_manager.create_node([NodeType.CVE.value], cve)
        cve_ids[cve["cve_id"]] = node_id
    stored_ids["cves"] = cve_ids

    technique_ids = {}
    techniques = [
        {"technique_id": "T1190", "name": "Exploit Public-Facing Application",
         "tactic": "Initial Access", "description": "Exploiting web application vulnerabilities",
         "mitigation": "Application isolation, WAF, patching",
         "detection": "Monitor web logs, IDS/IPS alerts",
         "platform": ["Windows", "Linux"], "permissions_required": ["None"]},
        {"technique_id": "T1021", "name": "Remote Services",
         "tactic": "Lateral Movement", "description": "Using RDP, SSH, WinRM for lateral movement",
         "mitigation": "Network segmentation, MFA, account monitoring",
         "detection": "Monitor authentication logs, anomalous remote connections",
         "platform": ["Windows", "Linux"], "permissions_required": ["User", "Admin"]},
        {"technique_id": "T1485", "name": "Data Destruction",
         "tactic": "Impact", "description": "Destruction of data on target systems",
         "mitigation": "Backups, MFA, least privilege",
         "detection": "Monitor file deletion events, backup failures",
         "platform": ["Windows", "Linux"], "permissions_required": ["Admin", "SYSTEM"]},
        {"technique_id": "T1530", "name": "Data from Information Repositories",
         "tactic": "Collection", "description": "Accessing sensitive data in databases and shares",
         "mitigation": "Data encryption, access controls, database monitoring",
         "detection": "Monitor database queries, file share access patterns",
         "platform": ["Windows", "Linux"], "permissions_required": ["User"]},
    ]
    for tech in techniques:
        node_id = await graph_manager.create_node([NodeType.MITRE_TECHNIQUE.value], tech)
        technique_ids[tech["technique_id"]] = node_id
    stored_ids["techniques"] = technique_ids

    await _create_relationships(stored_ids)
    logger.info("Seed data population complete", node_count=len(stored_ids))
    return stored_ids


async def _create_relationships(ids: Dict[str, Dict[str, str]]):
    relationships = [
        ("users", "user-001", "departments", "dept-001", RelationshipType.BELONGS_TO, {"since": "2020-03-10", "role": "Physician"}),
        ("users", "user-002", "departments", "dept-002", RelationshipType.BELONGS_TO, {"since": "2019-07-22", "role": "Radiologist"}),
        ("users", "user-003", "departments", "dept-003", RelationshipType.BELONGS_TO, {"since": "2018-01-15", "role": "IT Admin"}),
        ("users", "user-004", "departments", "dept-004", RelationshipType.BELONGS_TO, {"since": "2020-06-01", "role": "Admin Staff"}),
        ("users", "user-005", "departments", "dept-006", RelationshipType.BELONGS_TO, {"since": "2021-02-14", "role": "Cardiologist"}),
        ("users", "user-006", "departments", "dept-001", RelationshipType.BELONGS_TO, {"since": "2022-09-05", "role": "Nurse"}),
        ("users", "user-007", "departments", "dept-003", RelationshipType.BELONGS_TO, {"since": "2021-11-30", "role": "IT Support"}),
        ("users", "user-008", "departments", "dept-005", RelationshipType.BELONGS_TO, {"since": "2023-04-18", "role": "Pharmacist"}),

        ("users", "user-001", "roles", "role-002", RelationshipType.BELONGS_TO, {}),
        ("users", "user-002", "roles", "role-004", RelationshipType.BELONGS_TO, {}),
        ("users", "user-003", "roles", "role-001", RelationshipType.BELONGS_TO, {}),
        ("users", "user-004", "roles", "role-005", RelationshipType.BELONGS_TO, {}),
        ("users", "user-005", "roles", "role-002", RelationshipType.BELONGS_TO, {}),
        ("users", "user-006", "roles", "role-003", RelationshipType.BELONGS_TO, {}),
        ("users", "user-007", "roles", "role-005", RelationshipType.BELONGS_TO, {}),
        ("users", "user-008", "roles", "role-002", RelationshipType.BELONGS_TO, {}),

        ("users", "user-003", "servers", "srv-001", RelationshipType.CONTROLS, {}),
        ("users", "user-003", "servers", "srv-002", RelationshipType.CONTROLS, {}),
        ("users", "user-007", "servers", "srv-004", RelationshipType.CONTROLS, {}),

        ("users", "user-001", "applications", "app-001", RelationshipType.USES, {"frequency": "daily", "purpose": "Patient records"}),
        ("users", "user-002", "applications", "app-002", RelationshipType.USES, {"frequency": "daily", "purpose": "Medical imaging"}),
        ("users", "user-005", "applications", "app-001", RelationshipType.USES, {"frequency": "daily", "purpose": "Patient records"}),
        ("users", "user-006", "applications", "app-001", RelationshipType.USES, {"frequency": "daily", "purpose": "Patient records"}),
        ("users", "user-008", "applications", "app-005", RelationshipType.USES, {"frequency": "daily", "purpose": "Pharmacy"}),
        ("users", "user-003", "applications", "app-004", RelationshipType.USES, {"frequency": "weekly", "purpose": "Security monitoring"}),
        ("users", "user-004", "applications", "app-003", RelationshipType.USES, {"frequency": "daily", "purpose": "Email"}),

        ("applications", "app-001", "databases", "db-001", RelationshipType.DEPENDS_ON, {"dependency_type": "data", "critical": True}),
        ("applications", "app-002", "databases", "db-002", RelationshipType.DEPENDS_ON, {"dependency_type": "data", "critical": True}),
        ("applications", "app-003", "databases", "db-003", RelationshipType.DEPENDS_ON, {"dependency_type": "data", "critical": True}),
        ("applications", "app-005", "databases", "db-001", RelationshipType.DEPENDS_ON, {"dependency_type": "data", "critical": True}),

        ("applications", "app-001", "servers", "srv-004", RelationshipType.RUNS_ON, {"instance_count": 2, "resource_usage": "high"}),
        ("applications", "app-002", "servers", "srv-004", RelationshipType.RUNS_ON, {"instance_count": 1, "resource_usage": "high"}),
        ("applications", "app-003", "servers", "srv-005", RelationshipType.RUNS_ON, {"instance_count": 1, "resource_usage": "medium"}),
        ("applications", "app-004", "servers", "srv-001", RelationshipType.RUNS_ON, {"instance_count": 1, "resource_usage": "medium"}),
        ("applications", "app-005", "servers", "srv-004", RelationshipType.RUNS_ON, {"instance_count": 1, "resource_usage": "low"}),

        ("databases", "db-001", "servers", "srv-003", RelationshipType.RUNS_ON, {}),
        ("databases", "db-002", "servers", "srv-003", RelationshipType.RUNS_ON, {}),
        ("databases", "db-003", "servers", "srv-001", RelationshipType.RUNS_ON, {}),

        ("servers", "srv-001", "switches", "sw-001", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 1, "bandwidth": "10Gbps"}),
        ("servers", "srv-002", "switches", "sw-001", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 2, "bandwidth": "10Gbps"}),
        ("servers", "srv-003", "switches", "sw-001", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 3, "bandwidth": "10Gbps"}),
        ("servers", "srv-004", "switches", "sw-003", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 1, "bandwidth": "1Gbps"}),
        ("servers", "srv-005", "switches", "sw-001", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 4, "bandwidth": "1Gbps"}),
        ("servers", "srv-006", "switches", "sw-001", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 5, "bandwidth": "10Gbps"}),
        ("servers", "srv-007", "switches", "sw-003", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 2, "bandwidth": "1Gbps"}),

        ("iot_devices", "iot-001", "switches", "sw-001", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 10, "bandwidth": "1Gbps"}),
        ("iot_devices", "iot-002", "switches", "sw-001", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 11, "bandwidth": "1Gbps"}),
        ("iot_devices", "iot-003", "switches", "sw-001", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 12, "bandwidth": "1Gbps"}),
        ("iot_devices", "iot-004", "switches", "sw-001", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 13, "bandwidth": "1Gbps"}),
        ("iot_devices", "iot-005", "switches", "sw-001", RelationshipType.CONNECTED_TO, {"protocol": "Ethernet", "port": 14, "bandwidth": "1Gbps"}),

        ("iot_devices", "iot-001", "servers", "srv-004", RelationshipType.COMMUNICATES_WITH, {"protocol": "DICOM", "frequency": "real-time", "data_type": "medical_images"}),
        ("iot_devices", "iot-002", "servers", "srv-004", RelationshipType.COMMUNICATES_WITH, {"protocol": "DICOM", "frequency": "real-time", "data_type": "medical_images"}),
        ("iot_devices", "iot-003", "servers", "srv-004", RelationshipType.COMMUNICATES_WITH, {"protocol": "DICOM", "frequency": "real-time", "data_type": "medical_images"}),

        ("firewalls", "fw-001", "switches", "sw-001", RelationshipType.CONTROLS, {"control_type": "north-south", "effective": True}),
        ("firewalls", "fw-002", "switches", "sw-003", RelationshipType.CONTROLS, {"control_type": "east-west", "effective": True}),
        ("firewalls", "fw-001", "switches", "sw-002", RelationshipType.CONTROLS, {"control_type": "redundant", "effective": True}),

        ("vpn", "vpn-001", "firewalls", "fw-001", RelationshipType.CONNECTED_TO, {"protocol": "IPSec", "port": 1194, "bandwidth": "1Gbps"}),

        ("servers", "srv-004", "firewalls", "fw-002", RelationshipType.PROTECTED_BY, {"protection_type": "dmz", "rule_id": "RULE-001", "active": True}),
        ("servers", "srv-007", "firewalls", "fw-002", RelationshipType.PROTECTED_BY, {"protection_type": "dmz", "rule_id": "RULE-001", "active": True}),
        ("databases", "db-001", "firewalls", "fw-001", RelationshipType.PROTECTED_BY, {"protection_type": "internal", "rule_id": "RULE-050", "active": True}),

        ("threat_actors", "ta-001", "cves", "CVE-2024-001", RelationshipType.EXPLOITS, {"technique": "SQL injection", "vector": "web", "success_rate": 0.85, "complexity": "low", "detected": False}),
        ("threat_actors", "ta-002", "cves", "CVE-2024-002", RelationshipType.EXPLOITS, {"technique": "Privilege escalation", "vector": "email", "success_rate": 0.75, "complexity": "medium", "detected": False}),
        ("threat_actors", "ta-001", "cves", "CVE-2024-003", RelationshipType.EXPLOITS, {"technique": "Buffer overflow", "vector": "adjacent", "success_rate": 0.6, "complexity": "medium", "detected": False}),
        ("threat_actors", "ta-002", "cves", "CVE-2024-004", RelationshipType.EXPLOITS, {"technique": "RCE", "vector": "network", "success_rate": 0.9, "complexity": "low", "detected": False}),

        ("threat_actors", "ta-001", "applications", "app-001", RelationshipType.TARGETS, {"motivation": "patient data", "method": "SQLi", "likelihood": "high", "impact": "critical"}),
        ("threat_actors", "ta-002", "departments", "dept-003", RelationshipType.TARGETS, {"motivation": "ransom", "method": "phishing", "likelihood": "high", "impact": "critical"}),
        ("threat_actors", "ta-002", "departments", "dept-001", RelationshipType.TARGETS, {"motivation": "ransom", "method": "lateral", "likelihood": "medium", "impact": "critical"}),

        ("cves", "CVE-2024-001", "applications", "app-001", RelationshipType.TARGETS, {}),
        ("cves", "CVE-2024-002", "applications", "app-003", RelationshipType.TARGETS, {}),
        ("cves", "CVE-2024-003", "iot_devices", "iot-001", RelationshipType.TARGETS, {}),
        ("cves", "CVE-2024-004", "firewalls", "fw-001", RelationshipType.TARGETS, {}),

        ("users", "user-003", "credentials", "cred-003", RelationshipType.USES, {"frequency": "daily", "purpose": "server access"}),

        ("servers", "srv-001", "credentials", "cred-003", RelationshipType.HAS_ACCOUNT, {"account_type": "root", "privilege_level": "admin"}),

        ("identities", "id-001", "users", "user-003", RelationshipType.HAS_ACCOUNT, {"account_type": "federated", "privilege_level": "admin"}),
        ("identities", "id-002", "users", "user-001", RelationshipType.HAS_ACCOUNT, {"account_type": "federated", "privilege_level": "user"}),

        ("roles", "role-001", "servers", "srv-001", RelationshipType.CAN_ACCESS, {"access_type": "full", "authorized": True}),
        ("roles", "role-001", "databases", "db-001", RelationshipType.CAN_ACCESS, {"access_type": "full", "authorized": True}),
        ("roles", "role-001", "applications", "app-004", RelationshipType.CAN_ACCESS, {"access_type": "admin", "authorized": True}),
        ("roles", "role-002", "applications", "app-001", RelationshipType.CAN_ACCESS, {"access_type": "read_write", "authorized": True}),
        ("roles", "role-002", "applications", "app-002", RelationshipType.CAN_ACCESS, {"access_type": "read", "authorized": True}),
        ("roles", "role-004", "applications", "app-002", RelationshipType.CAN_ACCESS, {"access_type": "admin", "authorized": True}),
        ("roles", "role-003", "applications", "app-001", RelationshipType.CAN_ACCESS, {"access_type": "read", "authorized": True}),
        ("roles", "role-005", "servers", "srv-001", RelationshipType.CAN_ACCESS, {"access_type": "read", "authorized": True}),

        ("cloud_services", "cs-001", "servers", "srv-006", RelationshipType.DEPENDS_ON, {"dependency_type": "backup_target", "critical": True}),

        ("policies", "pol-001", "departments", "dept-001", RelationshipType.CONTROLS, {"control_type": "compliance", "effective": True}),
        ("policies", "pol-002", "users", "user-001", RelationshipType.CONTROLS, {"control_type": "security", "effective": False}),
        ("policies", "pol-003", "firewalls", "fw-001", RelationshipType.CONTROLS, {"control_type": "network", "effective": True}),
    ]

    for source_category, source_key, target_category, target_key, rel_type, props in relationships:
        source_id = ids[source_category][source_key]
        target_id = ids[target_category][target_key]
        await graph_manager.create_relationship(source_id, target_id, rel_type.value, props)
