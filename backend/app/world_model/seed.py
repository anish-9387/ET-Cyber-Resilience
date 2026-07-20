from __future__ import annotations

from typing import Any, Dict, List


SEED_NAME = "indian_government_hospital_cni"
SEED_VERSION = "1.0.0"


ENTITIES: List[Dict[str, Any]] = [
    {"id": "dept-cardiology", "name": "Cardiology", "entity_type": "department", "criticality": "high",
     "mission_functions": ["patient_care", "diagnostics"],
     "attributes": {"location": "3rd Floor, East Wing", "head_count": 35}},
    {"id": "dept-radiology", "name": "Radiology", "entity_type": "department", "criticality": "high",
     "mission_functions": ["diagnostics"],
     "attributes": {"location": "Ground Floor, West Wing", "head_count": 30}},
    {"id": "dept-emergency", "name": "Emergency", "entity_type": "department", "criticality": "critical",
     "mission_functions": ["emergency_response", "patient_care"],
     "attributes": {"location": "Ground Floor, East Wing", "head_count": 45}},
    {"id": "dept-it", "name": "Information Technology", "entity_type": "department", "criticality": "critical",
     "mission_functions": ["records_availability"],
     "attributes": {"location": "Basement, Server Room", "head_count": 25}},
    {"id": "dept-admin", "name": "Administration", "entity_type": "department", "criticality": "medium",
     "mission_functions": ["records_availability"],
     "attributes": {"location": "2nd Floor", "head_count": 60}},

    {"id": "user-001", "name": "Dr. Rajesh Kumar", "entity_type": "user", "criticality": "medium",
     "mission_functions": ["patient_care"],
     "attributes": {"role": "Doctor", "department": "Cardiology", "email": "rajesh.kumar@gov-hospital.in",
                    "clearance_level": 3, "mfa_enabled": False}},
    {"id": "user-002", "name": "Dr. Priya Sharma", "entity_type": "user", "criticality": "medium",
     "mission_functions": ["diagnostics"],
     "attributes": {"role": "Doctor", "department": "Radiology", "email": "priya.sharma@gov-hospital.in",
                    "clearance_level": 4, "mfa_enabled": True}},
    {"id": "user-003", "name": "Nurse Anita Devi", "entity_type": "user", "criticality": "medium",
     "mission_functions": ["emergency_response", "patient_care"],
     "attributes": {"role": "Nurse", "department": "Emergency", "email": "anita.devi@gov-hospital.in",
                    "clearance_level": 2, "mfa_enabled": False}},
    {"id": "user-004", "name": "Admin Vikram Singh", "entity_type": "user", "criticality": "critical",
     "mission_functions": ["records_availability"],
     "attributes": {"role": "System Admin", "department": "IT", "email": "vikram.singh@gov-hospital.in",
                    "clearance_level": 5, "mfa_enabled": True, "privileged": True}},
    {"id": "user-005", "name": "Security Analyst Arjun", "entity_type": "user", "criticality": "high",
     "mission_functions": ["records_availability"],
     "attributes": {"role": "Security Analyst", "department": "IT", "email": "arjun.sec@gov-hospital.in",
                    "clearance_level": 4, "mfa_enabled": True, "privileged": True}},
    {"id": "user-006", "name": "Network Admin Sneha", "entity_type": "user", "criticality": "critical",
     "mission_functions": ["records_availability", "power_supply"],
     "attributes": {"role": "Network Admin", "department": "IT", "email": "sneha.net@gov-hospital.in",
                    "clearance_level": 5, "mfa_enabled": False, "privileged": True}},
    {"id": "user-007", "name": "Dr. Meera Patel", "entity_type": "user", "criticality": "medium",
     "mission_functions": ["emergency_response"],
     "attributes": {"role": "Doctor", "department": "Emergency", "email": "meera.patel@gov-hospital.in",
                    "clearance_level": 4, "mfa_enabled": False}},
    {"id": "user-008", "name": "Admin Rohit Gupta", "entity_type": "user", "criticality": "low",
     "mission_functions": ["records_availability"],
     "attributes": {"role": "HR Admin", "department": "Admin", "email": "rohit.gupta@gov-hospital.in",
                    "clearance_level": 3, "mfa_enabled": False}},
    {"id": "user-009", "name": "OT Engineer Karthik", "entity_type": "user", "criticality": "critical",
     "mission_functions": ["power_supply", "water_treatment"],
     "attributes": {"role": "OT Engineer", "department": "Facilities", "email": "karthik.ot@gov-hospital.in",
                    "clearance_level": 4, "mfa_enabled": False, "privileged": True}},

    {"id": "srv-ad-01", "name": "Domain Controller DC01", "entity_type": "server", "criticality": "critical",
     "mission_functions": ["patient_care", "emergency_response", "diagnostics", "records_availability"],
     "attributes": {"role": "Domain Controller", "ip": "10.0.1.5", "os": "Windows Server 2022",
                    "patch_level": "KB5020044", "last_patched": "2024-10-15"}},
    {"id": "srv-db-01", "name": "Database Server DBSRV01", "entity_type": "server", "criticality": "critical",
     "mission_functions": ["records_availability", "patient_care"],
     "attributes": {"role": "Database", "ip": "10.0.1.20", "os": "Windows Server 2022",
                    "patch_level": "KB5020044", "last_patched": "2024-10-10"}},
    {"id": "srv-ehr-01", "name": "EHR Server EHRSRV01", "entity_type": "server", "criticality": "critical",
     "mission_functions": ["patient_care", "emergency_response", "records_availability"],
     "attributes": {"role": "Application Server", "ip": "10.0.1.50", "os": "Windows Server 2022",
                    "patch_level": "KB5020044", "last_patched": "2024-09-20"}},
    {"id": "srv-pacs-01", "name": "PACS Server PACSSRV01", "entity_type": "server", "criticality": "high",
     "mission_functions": ["diagnostics"],
     "attributes": {"role": "Application Server", "ip": "10.0.1.60", "os": "Windows Server 2022",
                    "patch_level": "KB5018421", "last_patched": "2024-08-15"}},
    {"id": "srv-backup-01", "name": "Backup Server BACKUPSRV01", "entity_type": "server", "criticality": "critical",
     "mission_functions": ["records_availability"],
     "attributes": {"role": "Backup", "ip": "10.0.2.10", "os": "Ubuntu 22.04 LTS",
                    "patch_level": "5.15.0-1054", "last_patched": "2024-11-05", "immutable_snapshots": False}},
    {"id": "srv-file-01", "name": "File Server FILESRV01", "entity_type": "server", "criticality": "high",
     "mission_functions": ["records_availability"],
     "attributes": {"role": "File Server", "ip": "10.0.1.30", "os": "Windows Server 2022",
                    "patch_level": "KB5020044", "last_patched": "2024-10-10"}},
    {"id": "srv-mail-01", "name": "Mail Server MAILSRV01", "entity_type": "server", "criticality": "high",
     "mission_functions": ["records_availability"],
     "attributes": {"role": "Mail Server", "ip": "10.0.1.40", "os": "Ubuntu 22.04 LTS",
                    "patch_level": "5.15.0-1054", "last_patched": "2024-08-15", "internet_facing": True}},
    {"id": "srv-web-01", "name": "Web Server WEBSRV01", "entity_type": "server", "criticality": "medium",
     "mission_functions": ["records_availability"],
     "attributes": {"role": "Web Server", "ip": "10.0.1.10", "os": "Ubuntu 22.04 LTS",
                    "patch_level": "5.15.0-1054", "last_patched": "2024-10-28", "internet_facing": True}},
    {"id": "srv-siem-01", "name": "SIEM Collector SIEMSRV01", "entity_type": "server", "criticality": "high",
     "mission_functions": ["records_availability"],
     "attributes": {"role": "Security Monitoring", "ip": "10.0.2.20", "os": "Ubuntu 22.04 LTS",
                    "patch_level": "5.15.0-1054", "last_patched": "2024-11-01"}},

    {"id": "db-ehr-prod", "name": "EHR_PRODUCTION", "entity_type": "database", "criticality": "critical",
     "mission_functions": ["patient_care", "records_availability"],
     "attributes": {"db_type": "PostgreSQL", "version": "15.4", "size_gb": 2500.0,
                    "has_encryption": True, "is_replicated": True}},
    {"id": "db-pacs-archive", "name": "PACS_ARCHIVE", "entity_type": "database", "criticality": "high",
     "mission_functions": ["diagnostics"],
     "attributes": {"db_type": "PostgreSQL", "version": "15.2", "size_gb": 8000.0,
                    "has_encryption": True, "is_replicated": True}},
    {"id": "db-ad", "name": "ACTIVE_DIRECTORY_STORE", "entity_type": "database", "criticality": "critical",
     "mission_functions": ["records_availability"],
     "attributes": {"db_type": "NTDS", "version": "2022", "size_gb": 50.0,
                    "has_encryption": True, "is_replicated": True}},

    {"id": "app-ehr", "name": "Electronic Health Records", "entity_type": "application", "criticality": "critical",
     "mission_functions": ["patient_care", "emergency_response", "records_availability"],
     "attributes": {"vendor": "MediTech", "version": "6.2.1", "auth_method": "SAML",
                    "cves": ["CVE-2024-1709"], "internet_facing": True}},
    {"id": "app-pacs", "name": "PACS Imaging System", "entity_type": "application", "criticality": "high",
     "mission_functions": ["diagnostics"],
     "attributes": {"vendor": "GE Healthcare", "version": "4.8.0", "auth_method": "LDAP",
                    "cves": ["CVE-2023-46604"]}},
    {"id": "app-mail", "name": "Microsoft Exchange", "entity_type": "application", "criticality": "high",
     "mission_functions": ["records_availability"],
     "attributes": {"vendor": "Microsoft", "version": "2022", "auth_method": "OAuth",
                    "cves": ["CVE-2024-21412"], "internet_facing": True}},
    {"id": "app-sap", "name": "SAP ERP S/4HANA", "entity_type": "application", "criticality": "medium",
     "mission_functions": ["records_availability"],
     "attributes": {"vendor": "SAP", "version": "S/4HANA 2023", "auth_method": "SAML", "cves": []}},
    {"id": "app-dns", "name": "DNS Service", "entity_type": "application", "criticality": "high",
     "mission_functions": ["records_availability", "patient_care"],
     "attributes": {"vendor": "ISC", "version": "Bind 9.18", "auth_method": "none", "cves": []}},
    {"id": "app-siem", "name": "Splunk SIEM", "entity_type": "application", "criticality": "high",
     "mission_functions": ["records_availability"],
     "attributes": {"vendor": "Splunk", "version": "9.1.0", "auth_method": "SAML", "cves": []}},

    {"id": "fw-main-01", "name": "Main Firewall FW-CORE", "entity_type": "network_device", "criticality": "critical",
     "mission_functions": ["records_availability"],
     "attributes": {"device_type": "Firewall", "vendor": "Palo Alto", "model": "PA-5250",
                    "ip": "10.0.0.1", "cves": ["CVE-2024-3400"], "internet_facing": True}},
    {"id": "fw-dmz-01", "name": "DMZ Firewall FW-DMZ", "entity_type": "network_device", "criticality": "high",
     "mission_functions": ["records_availability"],
     "attributes": {"device_type": "Firewall", "vendor": "Palo Alto", "model": "PA-440",
                    "ip": "10.0.0.2", "internet_facing": True}},
    {"id": "sw-core-01", "name": "Core Switch SW-CORE-01", "entity_type": "network_device", "criticality": "critical",
     "mission_functions": ["patient_care", "diagnostics", "records_availability"],
     "attributes": {"device_type": "Switch", "vendor": "Cisco", "model": "Catalyst 9500", "ip": "10.0.0.10"}},
    {"id": "sw-access-01", "name": "Access Switch SW-ACCESS-01", "entity_type": "network_device", "criticality": "high",
     "mission_functions": ["diagnostics"],
     "attributes": {"device_type": "Switch", "vendor": "Cisco", "model": "Catalyst 9300", "ip": "10.0.0.20",
                    "segment": "10.0.3.0/24"}},
    {"id": "sw-ot-01", "name": "OT Switch SW-OT-01", "entity_type": "network_device", "criticality": "critical",
     "mission_functions": ["power_supply", "water_treatment"],
     "attributes": {"device_type": "Switch", "vendor": "Siemens", "model": "SCALANCE XC216",
                    "ip": "10.0.5.1", "segment": "10.0.5.0/24"}},
    {"id": "vpn-01", "name": "VPN Gateway", "entity_type": "network_device", "criticality": "high",
     "mission_functions": ["records_availability"],
     "attributes": {"device_type": "VPN", "vendor": "OpenVPN", "ip": "203.0.113.1",
                    "has_mfa": True, "internet_facing": True}},

    {"id": "iot-mri-01", "name": "MRI Scanner MRI-01", "entity_type": "iot_device", "criticality": "high",
     "mission_functions": ["diagnostics"],
     "attributes": {"device_type": "MRI Scanner", "manufacturer": "Siemens", "ip": "10.0.3.10",
                    "firmware_version": "3.2.1", "protocol": "DICOM", "cves": ["CVE-2024-003"],
                    "patchable": False}},
    {"id": "iot-ct-01", "name": "CT Scanner CT-01", "entity_type": "iot_device", "criticality": "high",
     "mission_functions": ["diagnostics", "emergency_response"],
     "attributes": {"device_type": "CT Scanner", "manufacturer": "GE Healthcare", "ip": "10.0.3.20",
                    "firmware_version": "2.8.4", "protocol": "DICOM", "patchable": False}},
    {"id": "iot-xray-01", "name": "X-Ray Machine XRAY-01", "entity_type": "iot_device", "criticality": "medium",
     "mission_functions": ["diagnostics"],
     "attributes": {"device_type": "X-Ray Machine", "manufacturer": "Philips", "ip": "10.0.3.30",
                    "firmware_version": "1.9.2", "protocol": "DICOM", "patchable": False}},
    {"id": "iot-pump-01", "name": "Infusion Pump PUMP-01", "entity_type": "iot_device", "criticality": "critical",
     "mission_functions": ["patient_care", "emergency_response"],
     "attributes": {"device_type": "Infusion Pump", "manufacturer": "Baxter", "ip": "10.0.4.10",
                    "firmware_version": "5.0.1", "protocol": "HL7", "life_critical": True, "patchable": False}},
    {"id": "iot-monitor-01", "name": "Heart Monitor MON-01", "entity_type": "iot_device", "criticality": "critical",
     "mission_functions": ["patient_care", "emergency_response"],
     "attributes": {"device_type": "Heart Monitor", "manufacturer": "Medtronic", "ip": "10.0.4.20",
                    "firmware_version": "4.3.0", "protocol": "HL7", "life_critical": True, "patchable": False}},

    {"id": "ot-hmi-01", "name": "SCADA HMI Workstation", "entity_type": "ot_device", "criticality": "critical",
     "mission_functions": ["power_supply", "water_treatment"],
     "attributes": {"device_type": "HMI", "vendor": "Siemens WinCC", "ip": "10.0.5.10",
                    "os": "Windows 10 LTSC", "purdue_level": 2}},
    {"id": "ot-historian-01", "name": "Process Historian", "entity_type": "ot_device", "criticality": "high",
     "mission_functions": ["power_supply", "water_treatment"],
     "attributes": {"device_type": "Historian", "vendor": "OSIsoft PI", "ip": "10.0.5.20",
                    "os": "Windows Server 2019", "purdue_level": 3}},
    {"id": "ot-plc-power-01", "name": "Power Distribution PLC", "entity_type": "ot_device", "criticality": "critical",
     "mission_functions": ["power_supply"],
     "attributes": {"device_type": "PLC", "vendor": "Siemens S7-1500", "ip": "10.0.5.30",
                    "protocol": "S7comm", "purdue_level": 1, "safety_critical": True, "patchable": False}},
    {"id": "ot-plc-water-01", "name": "Water Treatment PLC", "entity_type": "ot_device", "criticality": "critical",
     "mission_functions": ["water_treatment"],
     "attributes": {"device_type": "PLC", "vendor": "Allen-Bradley ControlLogix", "ip": "10.0.5.40",
                    "protocol": "EtherNet/IP", "purdue_level": 1, "safety_critical": True, "patchable": False}},
    {"id": "ot-ups-01", "name": "Hospital UPS Controller", "entity_type": "ot_device", "criticality": "critical",
     "mission_functions": ["power_supply", "emergency_response"],
     "attributes": {"device_type": "UPS Controller", "vendor": "APC", "ip": "10.0.5.50",
                    "protocol": "SNMP", "purdue_level": 2, "safety_critical": True}},
    {"id": "ot-hvac-01", "name": "OT HVAC Controller", "entity_type": "ot_device", "criticality": "high",
     "mission_functions": ["patient_care"],
     "attributes": {"device_type": "BMS Controller", "vendor": "Honeywell", "ip": "10.0.5.60",
                    "protocol": "BACnet", "purdue_level": 2}},

    {"id": "cred-domain-admin", "name": "Domain Admin Credential", "entity_type": "credential", "criticality": "critical",
     "mission_functions": ["records_availability"],
     "attributes": {"credential_type": "password", "username": "hospital\\da_vikram",
                    "strength": "strong", "last_rotated": "2024-06-01", "stored_securely": True}},
    {"id": "cred-svc-ehr", "name": "EHR Service Account", "entity_type": "credential", "criticality": "critical",
     "mission_functions": ["patient_care", "records_availability"],
     "attributes": {"credential_type": "password", "username": "svc_ehr",
                    "strength": "medium", "last_rotated": "2024-06-01", "stored_securely": True}},
    {"id": "cred-backup-admin", "name": "Backup Admin Credential", "entity_type": "credential", "criticality": "critical",
     "mission_functions": ["records_availability"],
     "attributes": {"credential_type": "password", "username": "backup_admin",
                    "strength": "weak", "last_rotated": "2024-01-15", "stored_securely": False}},
    {"id": "cred-root-db", "name": "Database Root SSH Key", "entity_type": "credential", "criticality": "critical",
     "mission_functions": ["records_availability"],
     "attributes": {"credential_type": "ssh_key", "username": "root",
                    "strength": "strong", "last_rotated": "2023-11-20", "stored_securely": False}},
    {"id": "cred-ot-eng", "name": "OT Engineering Workstation Credential", "entity_type": "credential",
     "criticality": "critical", "mission_functions": ["power_supply", "water_treatment"],
     "attributes": {"credential_type": "password", "username": "ot_engineer",
                    "strength": "weak", "last_rotated": "2023-05-01", "stored_securely": False}},

    # Endpoints. These are the assets telemetry actually originates from and the
    # initial footholds in every replayable scenario, so they are modelled as
    # first-class graph nodes rather than being discovered at ingest time.
    {"id": "ws-hosp-ws041", "name": "Ward Workstation HOSP-WS041", "entity_type": "workstation",
     "criticality": "medium", "mission_functions": ["patient_care", "emergency_response"],
     "attributes": {"role": "Clinical Workstation", "ip": "10.20.14.41", "os": "Windows 11 22H2",
                    "assigned_to": "user-003", "segment": "ward", "mfa_enabled": False}},
    {"id": "ws-corp-ws112", "name": "Executive Workstation CORP-WS112", "entity_type": "workstation",
     "criticality": "medium", "mission_functions": ["records_availability"],
     "attributes": {"role": "Office Workstation", "ip": "10.44.12.112", "os": "Windows 11 22H2",
                    "assigned_to": "user-008", "segment": "corporate", "mfa_enabled": False}},
    {"id": "ws-corp-jump01", "name": "Admin Jump Host CORP-JUMP01", "entity_type": "workstation",
     "criticality": "high", "mission_functions": ["records_availability"],
     "attributes": {"role": "Privileged Access Workstation", "ip": "10.44.30.9", "os": "Ubuntu 22.04 LTS",
                    "assigned_to": "user-004", "segment": "management", "privileged": True}},
    {"id": "ws-wtr-eng02", "name": "OT Engineering Workstation WTR-ENG02", "entity_type": "workstation",
     "criticality": "critical", "mission_functions": ["water_treatment", "power_supply"],
     "attributes": {"role": "OT Engineering Workstation", "ip": "172.19.4.12", "os": "Windows 10 LTSC",
                    "assigned_to": "user-009", "segment": "ot_dmz", "purdue_level": 3,
                    "internet_facing": True, "mfa_enabled": False}},
]


RELATIONS: List[Dict[str, Any]] = [
    {"source": "user-001", "target": "dept-cardiology", "type": "belongs_to"},
    {"source": "user-002", "target": "dept-radiology", "type": "belongs_to"},
    {"source": "user-003", "target": "dept-emergency", "type": "belongs_to"},
    {"source": "user-004", "target": "dept-it", "type": "belongs_to"},
    {"source": "user-005", "target": "dept-it", "type": "belongs_to"},
    {"source": "user-006", "target": "dept-it", "type": "belongs_to"},
    {"source": "user-007", "target": "dept-emergency", "type": "belongs_to"},
    {"source": "user-008", "target": "dept-admin", "type": "belongs_to"},
    {"source": "user-009", "target": "dept-it", "type": "belongs_to"},

    {"source": "user-001", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "user-002", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "user-003", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "user-004", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "user-005", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "user-006", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "user-007", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "user-008", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "user-009", "target": "srv-ad-01", "type": "authenticates_to"},

    {"source": "srv-ehr-01", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "srv-pacs-01", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "srv-file-01", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "srv-db-01", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "srv-mail-01", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "srv-backup-01", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "ot-hmi-01", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "ot-historian-01", "target": "srv-ad-01", "type": "authenticates_to"},

    {"source": "user-004", "target": "cred-domain-admin", "type": "has_credential"},
    {"source": "user-006", "target": "cred-domain-admin", "type": "has_credential"},
    {"source": "user-004", "target": "cred-backup-admin", "type": "has_credential"},
    {"source": "user-005", "target": "cred-root-db", "type": "has_credential"},
    {"source": "user-009", "target": "cred-ot-eng", "type": "has_credential"},

    {"source": "cred-domain-admin", "target": "srv-ad-01", "type": "grants_access_to"},
    {"source": "cred-domain-admin", "target": "srv-ehr-01", "type": "grants_access_to"},
    {"source": "cred-svc-ehr", "target": "srv-ehr-01", "type": "grants_access_to"},
    {"source": "cred-svc-ehr", "target": "db-ehr-prod", "type": "grants_access_to"},
    {"source": "cred-backup-admin", "target": "srv-backup-01", "type": "grants_access_to"},
    {"source": "cred-root-db", "target": "srv-db-01", "type": "grants_access_to"},
    {"source": "cred-ot-eng", "target": "ot-hmi-01", "type": "grants_access_to"},

    {"source": "user-001", "target": "srv-ehr-01", "type": "can_access"},
    {"source": "user-002", "target": "srv-pacs-01", "type": "can_access"},
    {"source": "user-003", "target": "srv-ehr-01", "type": "can_access"},
    {"source": "user-004", "target": "srv-ad-01", "type": "can_access"},
    {"source": "user-004", "target": "srv-db-01", "type": "can_access"},
    {"source": "user-004", "target": "srv-backup-01", "type": "can_access"},
    {"source": "user-005", "target": "srv-siem-01", "type": "can_access"},
    {"source": "user-006", "target": "sw-core-01", "type": "can_access"},
    {"source": "user-006", "target": "fw-main-01", "type": "can_access"},
    {"source": "user-007", "target": "srv-ehr-01", "type": "can_access"},
    {"source": "user-009", "target": "ot-hmi-01", "type": "can_access"},

    {"source": "app-ehr", "target": "srv-ehr-01", "type": "runs_on"},
    {"source": "app-pacs", "target": "srv-pacs-01", "type": "runs_on"},
    {"source": "app-mail", "target": "srv-mail-01", "type": "runs_on"},
    {"source": "app-sap", "target": "srv-db-01", "type": "runs_on"},
    {"source": "app-dns", "target": "srv-ad-01", "type": "runs_on"},
    {"source": "app-siem", "target": "srv-siem-01", "type": "runs_on"},

    {"source": "db-ehr-prod", "target": "srv-db-01", "type": "runs_on"},
    {"source": "db-pacs-archive", "target": "srv-db-01", "type": "runs_on"},
    {"source": "db-ad", "target": "srv-ad-01", "type": "runs_on"},

    {"source": "app-ehr", "target": "db-ehr-prod", "type": "depends_on"},
    {"source": "app-pacs", "target": "db-pacs-archive", "type": "depends_on"},
    {"source": "app-ehr", "target": "app-dns", "type": "depends_on"},
    {"source": "app-pacs", "target": "app-dns", "type": "depends_on"},

    {"source": "srv-backup-01", "target": "db-ehr-prod", "type": "backs_up"},
    {"source": "srv-backup-01", "target": "db-pacs-archive", "type": "backs_up"},
    {"source": "srv-backup-01", "target": "srv-ad-01", "type": "backs_up"},

    {"source": "srv-ad-01", "target": "sw-core-01", "type": "connected_to"},
    {"source": "srv-db-01", "target": "sw-core-01", "type": "connected_to"},
    {"source": "srv-ehr-01", "target": "sw-core-01", "type": "connected_to"},
    {"source": "srv-pacs-01", "target": "sw-core-01", "type": "connected_to"},
    {"source": "srv-file-01", "target": "sw-core-01", "type": "connected_to"},
    {"source": "srv-backup-01", "target": "sw-core-01", "type": "connected_to"},
    {"source": "srv-siem-01", "target": "sw-core-01", "type": "connected_to"},
    {"source": "srv-mail-01", "target": "sw-access-01", "type": "connected_to"},
    {"source": "srv-web-01", "target": "sw-access-01", "type": "connected_to"},
    {"source": "sw-access-01", "target": "sw-core-01", "type": "connected_to"},
    {"source": "sw-ot-01", "target": "sw-core-01", "type": "connected_to"},

    {"source": "iot-mri-01", "target": "sw-access-01", "type": "connected_to"},
    {"source": "iot-ct-01", "target": "sw-access-01", "type": "connected_to"},
    {"source": "iot-xray-01", "target": "sw-access-01", "type": "connected_to"},
    {"source": "iot-pump-01", "target": "sw-access-01", "type": "connected_to"},
    {"source": "iot-monitor-01", "target": "sw-access-01", "type": "connected_to"},

    {"source": "iot-mri-01", "target": "srv-pacs-01", "type": "communicates_with"},
    {"source": "iot-ct-01", "target": "srv-pacs-01", "type": "communicates_with"},
    {"source": "iot-xray-01", "target": "srv-pacs-01", "type": "communicates_with"},
    {"source": "iot-pump-01", "target": "srv-ehr-01", "type": "communicates_with"},
    {"source": "iot-monitor-01", "target": "srv-ehr-01", "type": "communicates_with"},

    {"source": "ot-hmi-01", "target": "sw-ot-01", "type": "connected_to"},
    {"source": "ot-historian-01", "target": "sw-ot-01", "type": "connected_to"},
    {"source": "ot-plc-power-01", "target": "sw-ot-01", "type": "connected_to"},
    {"source": "ot-plc-water-01", "target": "sw-ot-01", "type": "connected_to"},
    {"source": "ot-ups-01", "target": "sw-ot-01", "type": "connected_to"},
    {"source": "ot-hvac-01", "target": "sw-ot-01", "type": "connected_to"},

    {"source": "ot-hmi-01", "target": "ot-plc-power-01", "type": "controls"},
    {"source": "ot-hmi-01", "target": "ot-plc-water-01", "type": "controls"},
    {"source": "ot-hmi-01", "target": "ot-ups-01", "type": "controls"},
    {"source": "ot-hmi-01", "target": "ot-hvac-01", "type": "controls"},
    {"source": "ot-historian-01", "target": "ot-plc-power-01", "type": "communicates_with"},
    {"source": "ot-historian-01", "target": "ot-plc-water-01", "type": "communicates_with"},

    {"source": "srv-web-01", "target": "fw-dmz-01", "type": "protected_by"},
    {"source": "srv-mail-01", "target": "fw-dmz-01", "type": "protected_by"},
    {"source": "sw-core-01", "target": "fw-main-01", "type": "protected_by"},
    {"source": "sw-ot-01", "target": "fw-main-01", "type": "protected_by"},
    {"source": "vpn-01", "target": "fw-main-01", "type": "connected_to"},
    {"source": "fw-dmz-01", "target": "fw-main-01", "type": "connected_to"},

    {"source": "srv-ehr-01", "target": "iot-pump-01", "type": "depends_on"},
    {"source": "srv-ehr-01", "target": "iot-monitor-01", "type": "depends_on"},
    # Endpoint wiring: assigned user, domain authentication, switch uplink.
    {"source": "user-003", "target": "ws-hosp-ws041", "type": "can_access"},
    {"source": "ws-hosp-ws041", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "ws-hosp-ws041", "target": "sw-access-01", "type": "connected_to"},
    {"source": "ws-hosp-ws041", "target": "srv-ehr-01", "type": "communicates_with"},

    {"source": "user-008", "target": "ws-corp-ws112", "type": "can_access"},
    {"source": "ws-corp-ws112", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "ws-corp-ws112", "target": "sw-access-01", "type": "connected_to"},
    {"source": "ws-corp-ws112", "target": "srv-mail-01", "type": "communicates_with"},

    {"source": "user-004", "target": "ws-corp-jump01", "type": "can_access"},
    {"source": "ws-corp-jump01", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "ws-corp-jump01", "target": "sw-core-01", "type": "connected_to"},
    {"source": "ws-corp-jump01", "target": "srv-file-01", "type": "can_access"},
    {"source": "ws-corp-jump01", "target": "srv-db-01", "type": "can_access"},

    {"source": "user-009", "target": "ws-wtr-eng02", "type": "can_access"},
    {"source": "cred-ot-eng", "target": "ws-wtr-eng02", "type": "grants_access_to"},
    {"source": "ws-wtr-eng02", "target": "srv-ad-01", "type": "authenticates_to"},
    {"source": "ws-wtr-eng02", "target": "sw-ot-01", "type": "connected_to"},
    # Engineering control path down into the process network.
    {"source": "ws-wtr-eng02", "target": "ot-hmi-01", "type": "controls"},
    {"source": "ws-wtr-eng02", "target": "ot-plc-water-01", "type": "controls"},
    {"source": "ws-wtr-eng02", "target": "ot-historian-01", "type": "communicates_with"},

    {"source": "ot-ups-01", "target": "srv-ad-01", "type": "powers"},
    {"source": "ot-ups-01", "target": "srv-ehr-01", "type": "powers"},
    {"source": "ot-plc-power-01", "target": "ot-ups-01", "type": "powers"},
]


#: Hostnames each asset carries in real telemetry.
#:
#: Sensors never emit world-model ids - Windows sends `Computer`, syslog sends a
#: hostname, Wazuh sends an agent name. This table is what lets
#: `world_model.resolve()` land those observations on the modelled asset instead
#: of spawning an orphan node. The first entry is the asset's primary hostname.
TELEMETRY_HOSTNAMES: Dict[str, List[str]] = {
    # Hospital core
    "srv-ad-01": ["HOSP-DC01", "CORP-DC02", "MEDNET-DC01"],
    "srv-db-01": ["HOSP-DB01"],
    "srv-ehr-01": ["HOSP-EMR01", "HOSP-EHR01"],
    "srv-pacs-01": ["HOSP-PACS01"],
    "srv-backup-01": ["HOSP-BKP01", "HOSP-BACKUP01"],
    "srv-file-01": ["CORP-FS01", "HOSP-FS01"],
    "srv-mail-01": ["CORP-MAIL01", "HOSP-MAIL01"],
    "srv-web-01": ["HOSP-WEB01"],
    "srv-siem-01": ["HOSP-SIEM01"],

    # Network edge
    "vpn-01": ["HOSP-VPN01", "VPN01"],
    "fw-main-01": ["HOSP-FW01", "FW-CORE"],
    "fw-dmz-01": ["HOSP-FWDMZ01", "FW-DMZ"],
    "sw-core-01": ["SW-CORE-01"],
    "sw-access-01": ["SW-ACCESS-01"],
    "sw-ot-01": ["SW-OT-01"],

    # OT / process network
    "ot-hmi-01": ["WTR-HMI01"],
    "ot-historian-01": ["WTR-HIST01"],
    "ot-plc-water-01": ["WTR-PLC01"],
    "ot-plc-power-01": ["PWR-PLC01"],
    "ot-ups-01": ["HOSP-UPS01"],
    "ot-hvac-01": ["HOSP-HVAC01"],

    # Endpoints
    "ws-hosp-ws041": ["HOSP-WS041"],
    "ws-corp-ws112": ["CORP-WS112"],
    "ws-corp-jump01": ["CORP-JUMP01"],
    "ws-wtr-eng02": ["WTR-ENG02"],
}


def _short_name_alias(name: str) -> List[str]:
    """The trailing hostname-ish token of a display name, e.g. 'DC01'.

    Only tokens containing a digit qualify, so generic trailing words ('PLC',
    'Workstation') never become ambiguous aliases shared by two assets.
    """
    tokens = name.split()
    if len(tokens) < 2:
        return []
    last = tokens[-1]
    return [last] if any(character.isdigit() for character in last) else []


def build_seed() -> Dict[str, Any]:
    entities: List[Dict[str, Any]] = []
    for entity in ENTITIES:
        item = dict(entity)
        item["attributes"] = dict(item.get("attributes") or {})
        hostnames = TELEMETRY_HOSTNAMES.get(item["id"], [])
        aliases = set(item.get("aliases") or ())
        aliases.update(hostnames)
        aliases.update(_short_name_alias(item["name"]))
        item["aliases"] = sorted(aliases)
        if hostnames:
            item["attributes"]["hostname"] = hostnames[0]
            item["attributes"]["hostnames"] = list(hostnames)
        entities.append(item)

    return {
        "name": SEED_NAME,
        "version": SEED_VERSION,
        "description": "Indian government hospital critical national infrastructure topology",
        "entities": entities,
        "relations": [dict(relation) for relation in RELATIONS],
    }
