import asyncio
import json
import sys
import os
import random
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

API_BASE = "http://localhost:8000/api"

INCIDENTS = [
    {
        "title": "Ransomware Outbreak - LockBit 3.0",
        "description": "LockBit 3.0 ransomware deployed via compromised RDP credentials. Encrypted 5 file servers including EHR storage. Ransom demand of 50 BTC.",
        "severity": "critical",
        "status": "resolved",
        "mitre_techniques": ["T1566", "T1059", "T1003", "T1021", "T1486"],
        "affected_assets": ["srv-file-01", "srv-ehr-01", "srv-backup-01"],
        "detection_source": "EDR + Network Analytics",
        "mttr_minutes": 47,
        "timestamp": (datetime.utcnow() - timedelta(days=2)).isoformat()
    },
    {
        "title": "Phishing Campaign Targeting Cardiology Dept",
        "description": "Spear-phishing emails with malicious PDFs sent to 12 cardiology staff. 3 users clicked, 1 executed macro. AI blocked C2 before beacon established.",
        "severity": "high",
        "status": "resolved",
        "mitre_techniques": ["T1566", "T1204"],
        "affected_assets": ["ws-rajesh-01", "ws-meera-01"],
        "detection_source": "Email Gateway + EDR",
        "mttr_minutes": 8,
        "timestamp": (datetime.utcnow() - timedelta(days=5)).isoformat()
    },
    {
        "title": "Insider Threat - Unauthorized Data Access",
        "description": "Employee accessed patient records for 200+ individuals without authorization. Pattern detected by Behaviour Learning Agent as anomalous.",
        "severity": "high",
        "status": "investigating",
        "mitre_techniques": ["T1078", "T1530"],
        "affected_assets": ["srv-ehr-01"],
        "detection_source": "Behaviour Learning Agent",
        "mttr_minutes": 12,
        "timestamp": (datetime.utcnow() - timedelta(hours=6)).isoformat()
    },
    {
        "title": "DDoS Attack on Public-Facing Web Server",
        "description": "Layer 7 DDoS attack targeting hospital portal. 500K requests/minute from 10K+ IPs. Mitigated by WAF and rate limiting.",
        "severity": "medium",
        "status": "resolved",
        "mitre_techniques": ["T1498", "T1499"],
        "affected_assets": ["srv-web-01", "fw-main-01"],
        "detection_source": "Network Monitoring",
        "mttr_minutes": 34,
        "timestamp": (datetime.utcnow() - timedelta(days=1)).isoformat()
    },
    {
        "title": "Brute Force Attack on VPN Gateway",
        "description": "10,000+ failed authentication attempts on VPN gateway from 50+ IPs. Account lockout policy prevented breach.",
        "severity": "medium",
        "status": "resolved",
        "mitre_techniques": ["T1110"],
        "affected_assets": ["vpn-01"],
        "detection_source": "Firewall Logs",
        "mttr_minutes": 5,
        "timestamp": (datetime.utcnow() - timedelta(days=3)).isoformat()
    },
    {
        "title": "Malware on Radiology Workstation",
        "description": "Trojan downloaded on PACS workstation via infected USB drive. Device isolated before spread to PACS server.",
        "severity": "high",
        "status": "resolved",
        "mitre_techniques": ["T1204", "T1059"],
        "affected_assets": ["ws-radio-01", "srv-pacs-01"],
        "detection_source": "Endpoint Protection",
        "mttr_minutes": 15,
        "timestamp": (datetime.utcnow() - timedelta(days=7)).isoformat()
    },
    {
        "title": "Suspicious PowerShell on Domain Controller",
        "description": "PowerShell Empire framework detected on Domain Controller. Threat Prediction Agent flagged as lateral movement attempt from compromised IT admin account.",
        "severity": "critical",
        "status": "contained",
        "mitre_techniques": ["T1059", "T1078", "T1003"],
        "affected_assets": ["srv-ad-01", "ws-vikram-01"],
        "detection_source": "Threat Prediction Agent",
        "mttr_minutes": 3,
        "timestamp": (datetime.utcnow() - timedelta(hours=12)).isoformat()
    },
    {
        "title": "Data Exfiltration via DNS Tunneling",
        "description": "Patient data exfiltrated via DNS tunneling. 2GB transferred over 48 hours. Detected by anomalous DNS query patterns.",
        "severity": "critical",
        "status": "investigating",
        "mitre_techniques": ["T1048", "T1572"],
        "affected_assets": ["srv-ehr-01", "fw-dmz-01"],
        "detection_source": "Network Analytics + Behaviour Agent",
        "mttr_minutes": 0,
        "timestamp": (datetime.utcnow() - timedelta(hours=2)).isoformat()
    },
    {
        "title": "Misconfigured S3 Bucket Exposure",
        "description": "Backup bucket misconfiguration exposed 50K patient records. No evidence of unauthorized access. Corrected within 30 min of detection.",
        "severity": "high",
        "status": "resolved",
        "mitre_techniques": ["T1530"],
        "affected_assets": ["srv-backup-01"],
        "detection_source": "Cloud Security Scanner",
        "mttr_minutes": 30,
        "timestamp": (datetime.utcnow() - timedelta(days=10)).isoformat()
    },
    {
        "title": "Zero-Day Exploit - ScreenConnect CVE-2024-1709",
        "description": "ConnectWise ScreenConnect authentication bypass exploited on IT admin workstation. AI predicted escalation path and proactively blocked.",
        "severity": "critical",
        "status": "contained",
        "mitre_techniques": ["T1190", "T1068", "T1021"],
        "affected_assets": ["ws-vikram-01", "srv-db-01"],
        "detection_source": "Vulnerability Scanner + Threat Prediction",
        "mttr_minutes": 2,
        "timestamp": (datetime.utcnow() - timedelta(days=1)).isoformat()
    },
]


async def create_incident_api(incident):
    import httpx
    async with httpx.AsyncClient(timeout=10) as client:
        try:
            resp = await client.post(f"{API_BASE}/incidents", json=incident)
            if resp.status_code < 300:
                return resp.json()
            else:
                return None
        except httpx.ConnectError:
            return None


async def create_incident_direct(incident, index):
    print(f"  [{index+1}] {incident['title']}")
    print(f"       Severity: {incident['severity']}, Status: {incident['status']}")
    print(f"       MITRE: {', '.join(incident['mitre_techniques'])}")
    print(f"       MTTR: {incident['mttr_minutes']} minutes")
    print()


async def main():
    print("=" * 60)
    print("  Sentinel-X: Sample Incident Creator")
    print("=" * 60)
    print()

    use_api = False
    import httpx
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            resp = await client.get(f"{API_BASE}/health")
            if resp.status_code < 300:
                use_api = True
                print("  Backend API is available - using API to create incidents")
            else:
                print("  Backend API unavailable - displaying incidents only")
    except Exception:
        print("  Backend API unavailable - displaying incidents only")
    print()

    if use_api:
        print(f"  Creating {len(INCIDENTS)} sample incidents via API...")
        print()

        tasks = []
        for i, incident in enumerate(INCIDENTS):
            incident_copy = dict(incident)
            incident_copy["timestamp"] = incident.get("timestamp")
            tasks.append(create_incident_api(incident_copy))

        results = await asyncio.gather(*tasks)

        created = sum(1 for r in results if r is not None)
        print(f"  Successfully created {created}/{len(INCIDENTS)} incidents")
    else:
        print(f"  Displaying {len(INCIDENTS)} sample incidents:")
        print()
        for i, incident in enumerate(INCIDENTS):
            await create_incident_direct(incident, i)

    print("=" * 60)
    print("  Done!")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
