import asyncio
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

NEO4J_URI = os.getenv("NEO4J_URI", "bolt://localhost:7687")
NEO4J_USER = os.getenv("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.getenv("NEO4J_PASSWORD", "password")

USERS = [
    {"id": "user-001", "name": "Dr. Rajesh Kumar", "role": "Doctor", "department": "Cardiology", "email": "rajesh.kumar@gov-hospital.in", "phone": "+91-9876543210"},
    {"id": "user-002", "name": "Dr. Priya Sharma", "role": "Doctor", "department": "Radiology", "email": "priya.sharma@gov-hospital.in"},
    {"id": "user-003", "name": "Nurse Anita Devi", "role": "Nurse", "department": "Emergency", "email": "anita.devi@gov-hospital.in"},
    {"id": "user-004", "name": "Admin Vikram Singh", "role": "System Admin", "department": "IT", "email": "vikram.singh@gov-hospital.in"},
    {"id": "user-005", "name": "Security Analyst Arjun", "role": "Security Analyst", "department": "IT", "email": "arjun.sec@gov-hospital.in"},
    {"id": "user-006", "name": "Network Admin Sneha", "role": "Network Admin", "department": "IT", "email": "sneha.net@gov-hospital.in"},
    {"id": "user-007", "name": "Dr. Meera Patel", "role": "Doctor", "department": "Emergency", "email": "meera.patel@gov-hospital.in"},
    {"id": "user-008", "name": "Admin Rohit Gupta", "role": "HR Admin", "department": "Admin", "email": "rohit.gupta@gov-hospital.in"},
]

SERVERS = [
    {"id": "srv-web-01", "name": "Web Server 01", "type": "Web Server", "ip": "10.0.1.10", "os": "Ubuntu 22.04", "criticality": "high"},
    {"id": "srv-db-01", "name": "Database Server", "type": "Database", "ip": "10.0.1.20", "os": "Windows Server 2022", "criticality": "critical"},
    {"id": "srv-ad-01", "name": "Domain Controller", "type": "Active Directory", "ip": "10.0.1.5", "os": "Windows Server 2022", "criticality": "critical"},
    {"id": "srv-file-01", "name": "File Server", "type": "File Server", "ip": "10.0.1.30", "os": "Windows Server 2022", "criticality": "high"},
    {"id": "srv-mail-01", "name": "Email Server", "type": "Mail Server", "ip": "10.0.1.40", "os": "Ubuntu 22.04", "criticality": "high"},
    {"id": "srv-backup-01", "name": "Backup Server", "type": "Backup", "ip": "10.0.2.10", "os": "Ubuntu 22.04", "criticality": "high"},
    {"id": "srv-ehr-01", "name": "EHR Server", "type": "Application Server", "ip": "10.0.1.50", "os": "Windows Server 2022", "criticality": "critical"},
    {"id": "srv-pacs-01", "name": "PACS Server", "type": "Application Server", "ip": "10.0.1.60", "os": "Windows Server 2022", "criticality": "high"},
]

NETWORK_DEVICES = [
    {"id": "fw-main-01", "name": "Main Firewall", "type": "Firewall", "ip": "10.0.0.1", "vendor": "Fortinet"},
    {"id": "fw-dmz-01", "name": "DMZ Firewall", "type": "Firewall", "ip": "10.0.0.2", "vendor": "Fortinet"},
    {"id": "sw-core-01", "name": "Core Switch", "type": "Switch", "ip": "10.0.0.10", "vendor": "Cisco"},
    {"id": "sw-access-01", "name": "Access Switch", "type": "Switch", "ip": "10.0.0.20", "vendor": "Cisco"},
    {"id": "vpn-01", "name": "VPN Gateway", "type": "VPN", "ip": "203.0.113.1", "vendor": "Palo Alto"},
]

IOT_DEVICES = [
    {"id": "iot-mri-01", "name": "MRI Scanner 01", "type": "Medical Device", "ip": "10.0.3.10", "department": "Radiology"},
    {"id": "iot-ct-01", "name": "CT Scanner 01", "type": "Medical Device", "ip": "10.0.3.20", "department": "Radiology"},
    {"id": "iot-xray-01", "name": "X-Ray Machine", "type": "Medical Device", "ip": "10.0.3.30", "department": "Radiology"},
    {"id": "iot-pump-01", "name": "Infusion Pump 01", "type": "Medical Device", "ip": "10.0.4.10", "department": "Emergency"},
]

APPLICATIONS = [
    {"id": "app-ehr", "name": "Electronic Health Records", "type": "Healthcare", "version": "4.2.1"},
    {"id": "app-pacs", "name": "PACS Imaging System", "type": "Healthcare", "version": "3.8.0"},
    {"id": "app-mail", "name": "Microsoft Exchange", "type": "Communication", "version": "2022"},
    {"id": "app-sap", "name": "SAP ERP", "type": "ERP", "version": "S/4HANA 2023"},
    {"id": "app-dns", "name": "DNS Server", "type": "Infrastructure", "version": "Bind 9.18"},
]

CVES = [
    {"id": "CVE-2024-1709", "description": "ConnectWise ScreenConnect Authentication Bypass", "cvss": 10.0, "exploited": True, "in_kev": True},
    {"id": "CVE-2024-20666", "description": "BitLocker Encryption Bypass", "cvss": 6.6, "exploited": True, "in_kev": True},
    {"id": "CVE-2023-46604", "description": "Apache ActiveMQ RCE", "cvss": 10.0, "exploited": True, "in_kev": True},
    {"id": "CVE-2024-21412", "description": "Microsoft Defender SmartScreen Bypass", "cvss": 8.1, "exploited": True, "in_kev": False},
]

THREAT_ACTORS = [
    {"id": "apt-29", "name": "APT29 (Cozy Bear)", "country": "Russia", "motivation": "Espionage", "target_sectors": ["Government", "Healthcare", "IT"]},
    {"id": "apt-41", "name": "APT41 (Winnti)", "country": "China", "motivation": "Espionage & Theft", "target_sectors": ["Government", "Healthcare"]},
    {"id": "ransomware-gang", "name": "LockBit 3.0", "country": "Unknown", "motivation": "Financial", "target_sectors": ["Healthcare", "Government"]},
]

MITRE_TECHNIQUES = [
    {"id": "T1566", "name": "Phishing", "tactic": "Initial Access"},
    {"id": "T1204", "name": "User Execution", "tactic": "Execution"},
    {"id": "T1059", "name": "Command and Scripting Interpreter", "tactic": "Execution"},
    {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
    {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
    {"id": "T1486", "name": "Data Encrypted for Impact", "tactic": "Impact"},
    {"id": "T1078", "name": "Valid Accounts", "tactic": "Defense Evasion"},
    {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
]

POLICIES = [
    {"id": "pol-password", "name": "Password Policy", "description": "Minimum 12 chars, MFA required", "enforced": True},
    {"id": "pol-backup", "name": "Backup Policy", "description": "3-2-1 backup rule, daily backups", "enforced": True},
    {"id": "pol-access", "name": "Access Control Policy", "description": "Least privilege, RBAC", "enforced": True},
]


def create_entities(tx, label, items, id_field="id"):
    for item in items:
        props = {k: v for k, v in item.items()}
        if isinstance(props.get("target_sectors"), list):
            props["target_sectors"] = str(props["target_sectors"])
        query = f"""
        MERGE (n:{label} {{{id_field}: $id_value}})
        SET n += $props
        """
        tx.run(query, id_value=props.pop(id_field), props=props)


def create_relationships(tx):
    rels = [
        ("MATCH (u:User {{id: $uid}}), (d:Department {{id: $did}}) MERGE (u)-[:BELONGS_TO]->(d)", [
            {"uid": "user-001", "did": "dept-cardiology"},
            {"uid": "user-002", "did": "dept-radiology"},
            {"uid": "user-003", "did": "dept-emergency"},
            {"uid": "user-004", "did": "dept-it"},
            {"uid": "user-005", "did": "dept-it"},
            {"uid": "user-006", "did": "dept-it"},
            {"uid": "user-007", "did": "dept-emergency"},
            {"uid": "user-008", "did": "dept-admin"},
        ]),
        ("MATCH (s:Server {{id: $sid}}), (d:Department {{id: $did}}) MERGE (s)-[:MANAGED_BY]->(d)", [
            {"sid": "srv-ehr-01", "did": "dept-it"},
            {"sid": "srv-pacs-01", "did": "dept-radiology"},
            {"sid": "srv-ad-01", "did": "dept-it"},
        ]),
        ("MATCH (u:User {{id: $uid}}), (s:Server {{id: $sid}}) MERGE (u)-[:CAN_ACCESS]->(s)", [
            {"uid": "user-001", "sid": "srv-ehr-01"},
            {"uid": "user-002", "sid": "srv-pacs-01"},
            {"uid": "user-004", "sid": "srv-ad-01"},
            {"uid": "user-004", "sid": "srv-db-01"},
            {"uid": "user-005", "sid": "srv-ehr-01"},
            {"uid": "user-005", "sid": "srv-db-01"},
        ]),
        ("MATCH (s:Server {{id: $sid}}), (a:Application {{id: $aid}}) MERGE (s)-[:RUNS]->(a)", [
            {"sid": "srv-ehr-01", "aid": "app-ehr"},
            {"sid": "srv-pacs-01", "aid": "app-pacs"},
            {"sid": "srv-mail-01", "aid": "app-mail"},
            {"sid": "srv-db-01", "aid": "app-sap"},
        ]),
        ("MATCH (a:Application {{id: $aid}}), (c:CVE {{id: $cid}}) MERGE (a)-[:VULNERABLE_TO]->(c)", [
            {"aid": "app-ehr", "cid": "CVE-2024-1709"},
            {"aid": "app-pacs", "cid": "CVE-2023-46604"},
            {"aid": "app-mail", "cid": "CVE-2024-21412"},
        ]),
        ("MATCH (c:CVE {{id: $cid}}), (ta:ThreatActor {{id: $taid}}) MERGE (ta)-[:USES]->(c)", [
            {"cid": "CVE-2024-1709", "taid": "apt-29"},
            {"cid": "CVE-2023-46604", "taid": "apt-41"},
            {"cid": "CVE-2024-20666", "taid": "ransomware-gang"},
        ]),
        ("MATCH (nw:NetworkDevice {{id: $nwid}}), (s:Server {{id: $sid}}) MERGE (s)-[:CONNECTED_VIA]->(nw)", [
            {"nwid": "sw-core-01", "sid": "srv-ehr-01"},
            {"nwid": "sw-core-01", "sid": "srv-db-01"},
            {"nwid": "sw-access-01", "sid": "srv-web-01"},
            {"nwid": "fw-main-01", "sid": "srv-web-01"},
        ]),
        ("MATCH (iot:IoTDevice {{id: $iid}}), (nw:NetworkDevice {{id: $nwid}}) MERGE (iot)-[:CONNECTED_VIA]->(nw)", [
            {"iid": "iot-mri-01", "nwid": "sw-access-01"},
            {"iid": "iot-ct-01", "nwid": "sw-access-01"},
        ]),
        ("MATCH (ta:ThreatActor {{id: $taid}}), (mt:MITRETechnique {{id: $mtid}}) MERGE (ta)-[:EMPLOYS]->(mt)", [
            {"taid": "apt-29", "mtid": "T1566"},
            {"taid": "apt-29", "mtid": "T1059"},
            {"taid": "ransomware-gang", "mtid": "T1486"},
            {"taid": "ransomware-gang", "mtid": "T1078"},
        ]),
        ("MATCH (mt:MITRETechnique {{id: $mtid}}), (po:Policy {{id: $pid}}) MERGE (mt)-[:MITIGATED_BY]->(po)", [
            {"mtid": "T1566", "pid": "pol-access"},
            {"mtid": "T1486", "pid": "pol-backup"},
            {"mtid": "T1078", "pid": "pol-password"},
        ]),
        ("MATCH (u:User {{id: $uid}}), (dpt:Department {{id: $did}}) MERGE (u)-[:WORKS_IN]->(dpt)", [
            {"uid": "user-001", "did": "dept-cardiology"},
            {"uid": "user-002", "did": "dept-radiology"},
            {"uid": "user-003", "did": "dept-emergency"},
            {"uid": "user-004", "did": "dept-it"},
        ]),
    ]
    for query, params_list in rels:
        for params in params_list:
            tx.run(query, params)


async def main():
    print("=" * 60)
    print("Sentinel-X Knowledge Graph Seed Script")
    print("=" * 60)
    print(f"Connecting to Neo4j at {NEO4J_URI}")

    try:
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))
        driver.verify_connectivity()
        print("Connected successfully.")
    except Exception as e:
        print(f"Failed to connect to Neo4j: {e}")
        print("Make sure Neo4j is running and accessible.")
        print("Default: bolt://localhost:7687, user: neo4j, password: password")
        sys.exit(1)

    DEPARTMENTS = [
        {"id": "dept-cardiology", "name": "Cardiology", "location": "3rd Floor, East Wing"},
        {"id": "dept-radiology", "name": "Radiology", "location": "Ground Floor, West Wing"},
        {"id": "dept-emergency", "name": "Emergency", "location": "Ground Floor, East Wing"},
        {"id": "dept-it", "name": "Information Technology", "location": "Basement, Server Room"},
        {"id": "dept-admin", "name": "Administration", "location": "2nd Floor"},
    ]

    with driver.session() as session:
        session.execute_write(create_entities, "Department", DEPARTMENTS)
        print(f"  Created {len(DEPARTMENTS)} departments")

        session.execute_write(create_entities, "User", USERS)
        print(f"  Created {len(USERS)} users")

        session.execute_write(create_entities, "Server", SERVERS)
        print(f"  Created {len(SERVERS)} servers")

        session.execute_write(create_entities, "NetworkDevice", NETWORK_DEVICES)
        print(f"  Created {len(NETWORK_DEVICES)} network devices")

        session.execute_write(create_entities, "IoTDevice", IOT_DEVICES)
        print(f"  Created {len(IOT_DEVICES)} IoT devices")

        session.execute_write(create_entities, "Application", APPLICATIONS)
        print(f"  Created {len(APPLICATIONS)} applications")

        session.execute_write(create_entities, "CVE", CVES)
        print(f"  Created {len(CVES)} CVEs")

        session.execute_write(create_entities, "ThreatActor", THREAT_ACTORS)
        print(f"  Created {len(THREAT_ACTORS)} threat actors")

        session.execute_write(create_entities, "MITRETechnique", MITRE_TECHNIQUES)
        print(f"  Created {len(MITRE_TECHNIQUES)} MITRE techniques")

        session.execute_write(create_entities, "Policy", POLICIES)
        print(f"  Created {len(POLICIES)} policies")

        session.execute_write(create_relationships)
        print("  Created all relationships")

    driver.close()
    print("=" * 60)
    print("Knowledge graph seeded successfully!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
