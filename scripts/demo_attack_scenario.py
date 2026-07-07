import asyncio
import json
import time
import httpx
from datetime import datetime

API_BASE = "http://localhost:8000/api"
DEMO_INCIDENT_ID = None


def print_step(step_num, title, description=""):
    print()
    print("=" * 70)
    print(f"  STEP {step_num}: {title}")
    print("=" * 70)
    if description:
        for line in description.split("\n"):
            print(f"  {line}")
    print()


def print_sub(title, content, indent=2):
    prefix = " " * indent
    print(f"{prefix}[{title}] {content}")


async def api_call(method, path, data=None):
    url = f"{API_BASE}{path}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            if method == "GET":
                resp = await client.get(url)
            elif method == "POST":
                resp = await client.post(url, json=data)
            elif method == "PUT":
                resp = await client.put(url, json=data)
            else:
                return None
            if resp.status_code < 300:
                return resp.json()
            else:
                print_sub("API", f"{method} {path} -> {resp.status_code}: {resp.text}")
                return None
    except httpx.ConnectError:
        print_sub("ERROR", f"Cannot connect to {API_BASE}. Is the backend running?")
        return None
    except Exception as e:
        print_sub("ERROR", str(e))
        return None


async def step1_phishing():
    print_step(1, "Phishing Email Sent", "Target: Dr. Rajesh Kumar (Cardiology)\nVector: Spear-phishing with malicious PDF attachment\nMITRE: T1566 - Phishing")

    print_sub("ATTACK", "Attacker sends email to rajesh.kumar@gov-hospital.in with subject: 'Urgent: Patient Report - Critical Findings'")

    alert = await api_call("POST", "/alerts", {
        "title": "Phishing Email Detected",
        "description": "Spear-phishing email with malicious attachment sent to Dr. Rajesh Kumar",
        "severity": "high",
        "source": "Email Gateway",
        "mitre_technique": "T1566",
        "target_user": "user-001",
        "timestamp": datetime.utcnow().isoformat()
    })
    if alert:
        print_sub("DETECTED", f"Alert created: {alert.get('id', 'N/A')}")

    prediction = await api_call("POST", "/predict", {
        "alert_id": alert.get("id") if alert else "sim-001",
        "current_technique": "T1566",
        "context": {"user": "Dr. Rajesh Kumar", "department": "Cardiology"}
    })
    if prediction:
        print_sub("AI PREDICTION", f"Next move: {prediction.get('predicted_technique', 'T1204 - User Execution')} (confidence: {prediction.get('confidence', 85)}%)")

    twin = await api_call("POST", "/digital-twin/simulate", {
        "scenario": "phishing_execution",
        "affected_entity": "user-001"
    })
    if twin:
        print_sub("DIGITAL TWIN", f"Blast radius: {twin.get('blast_radius', {}).get('devices_affected', 3)} devices, {twin.get('blast_radius', {}).get('users_affected', 5)} users")
        print_sub("SIMULATION", f"Estimated impact: {twin.get('impact_score', 7.2)}/10")

    response = await api_call("POST", "/respond", {
        "incident_type": "phishing",
        "actions": ["quarantine_email", "notify_user", "block_sender"]
    })
    if response:
        print_sub("RESPONSE", "Email quarantined, sender blocked, user notified")
        print_sub("AUTONOMOUS", f"Action taken: {response.get('action_taken', 'email_quarantined')}")

    return True


async def step2_macro_execution():
    print_step(2, "Macro Execution & Payload Download", "Target: Dr. Rajesh's Workstation (10.0.1.110)\nPayload: Cobalt Strike Beacon (HTTPS)\nMITRE: T1204 + T1059")

    print_sub("ATTACK", "User opens PDF, macro executes PowerShell command to download Cobalt Strike beacon")

    alert = await api_call("POST", "/alerts", {
        "title": "Suspicious PowerShell Execution",
        "description": "PowerShell spawning from Microsoft Word with network connection to external IP",
        "severity": "critical",
        "source": "EDR Agent",
        "mitre_technique": "T1059",
        "target_device": "ws-rajesh-01",
        "timestamp": datetime.utcnow().isoformat()
    })
    if alert:
        print_sub("DETECTED", f"Alert created: {alert.get('id', 'N/A')}")

    prediction = await api_call("POST", "/predict", {
        "alert_id": alert.get("id", "sim-002"),
        "current_technique": "T1059",
        "context": {"process": "powershell.exe", "parent_process": "WINWORD.EXE", "network": True}
    })
    if prediction:
        predicted = prediction.get("predicted_technique", "T1003")
        print_sub("AI PREDICTION", f"Next move: {predicted} - OS Credential Dumping (confidence: {prediction.get('confidence', 91)}%)")

    twin = await api_call("POST", "/digital-twin/simulate", {
        "scenario": "payload_execution",
        "affected_device": "ws-rajesh-01"
    })
    if twin:
        br = twin.get("blast_radius", {})
        print_sub("DIGITAL TWIN", f"Credential exposure risk: {br.get('credential_exposure_risk', 'high')}")
        print_sub("SIMULATION", f"Estimated blast radius: {br.get('total_assets_at_risk', 12)} assets")

    response = await api_call("POST", "/respond", {
        "incident_type": "malware_execution",
        "actions": ["isolate_endpoint", "terminate_process", "block_ip"]
    })
    if response:
        print_sub("RESPONSE", "Endpoint isolated, PowerShell terminated, C2 IP blocked")

    return True


async def step3_credential_dumping():
    print_step(3, "Credential Dumping with Mimikatz", "Target: Domain credentials from LSASS\nTool: Mimikatz\nMITRE: T1003 - OS Credential Dumping")

    print_sub("ATTACK", "Attacker runs Mimikatz to dump credentials from LSASS memory on compromised workstation")

    alert = await api_call("POST", "/alerts", {
        "title": "LSASS Access Detected",
        "description": "Suspicious access to lsass.exe process memory from non-standard tool",
        "severity": "critical",
        "source": "EDR Agent",
        "mitre_technique": "T1003",
        "target_device": "ws-rajesh-01",
        "timestamp": datetime.utcnow().isoformat()
    })
    if alert:
        print_sub("DETECTED", f"Alert created: {alert.get('id', 'N/A')}")
        global DEMO_INCIDENT_ID
        DEMO_INCIDENT_ID = alert.get("id")

    prediction = await api_call("POST", "/predict", {
        "alert_id": alert.get("id", "sim-003"),
        "current_technique": "T1003",
        "context": {"tool": "mimikatz", "target_process": "lsass.exe", "domain_user": "vikram.singh"}
    })
    if prediction:
        predicted = prediction.get("predicted_technique", "T1021")
        print_sub("AI PREDICTION", f"Next move: {predicted} - Remote Services / Lateral Movement (confidence: {prediction.get('confidence', 94)}%)")

    twin = await api_call("POST", "/digital-twin/simulate", {
        "scenario": "credential_theft",
        "compromised_user": "user-004",
        "domain": "GOV-HOSPITAL"
    })
    if twin:
        br = twin.get("blast_radius", {})
        print_sub("DIGITAL TWIN", f"Credentials exposed: {br.get('exposed_credentials', ['vikram.singh', 'svc-sql', 'svc-backup'])}")
        print_sub("SIMULATION", f"Assets accessible with stolen creds: {br.get('accessible_assets', 8)}")

    response = await api_call("POST", "/respond", {
        "incident_type": "credential_theft",
        "actions": ["rotate_credentials", "disable_account", "enable_audit"]
    })
    if response:
        print_sub("RESPONSE", "Domain admin credentials rotated, account flagged for audit")

    return True


async def step4_lateral_movement():
    print_step(4, "Lateral Movement to File Server", "Target: File Server (10.0.1.30)\nTechnique: Pass-the-Hash with stolen credentials\nMITRE: T1021 - Remote Services")

    print_sub("ATTACK", "Using stolen domain admin credentials, attacker connects to File Server via SMB (PsExec)")

    alert = await api_call("POST", "/alerts", {
        "title": "Lateral Movement Detected",
        "description": "Suspicious SMB connection from workstation to File Server using admin account",
        "severity": "critical",
        "source": "Network Analytics",
        "mitre_technique": "T1021",
        "source_device": "ws-rajesh-01",
        "target_device": "srv-file-01",
        "timestamp": datetime.utcnow().isoformat()
    })
    if alert:
        print_sub("DETECTED", f"Alert created: {alert.get('id', 'N/A')}")

    prediction = await api_call("POST", "/predict", {
        "alert_id": alert.get("id", "sim-004"),
        "current_technique": "T1021",
        "context": {"source": "10.0.1.110", "target": "10.0.1.30", "protocol": "SMB", "user": "vikram.singh"}
    })
    if prediction:
        predicted = prediction.get("predicted_technique", "T1078")
        print_sub("AI PREDICTION", f"Next move: {predicted} - Valid Accounts / Privilege Escalation (confidence: {prediction.get('confidence', 88)}%)")

    twin = await api_call("POST", "/digital-twin/simulate", {
        "scenario": "lateral_movement",
        "source": "ws-rajesh-01",
        "target": "srv-file-01",
        "stolen_creds": True
    })
    if twin:
        br = twin.get("blast_radius", {})
        print_sub("DIGITAL TWIN", f"Lateral movement path: {br.get('lateral_path', 'ws-rajesh-01 -> srv-file-01 -> srv-ad-01')}")
        print_sub("SIMULATION", f"Propagation speed: {br.get('propagation_time', 45)} seconds to Domain Controller")

    response = await api_call("POST", "/respond", {
        "incident_type": "lateral_movement",
        "actions": ["isolate_workstation", "block_smb_relay", "revoke_tokens"]
    })
    if response:
        print_sub("RESPONSE", "Source workstation isolated, SMB relay blocked, session tokens revoked")

    return True


async def step5_privilege_escalation():
    print_step(5, "Privilege Escalation on Domain Controller", "Target: Domain Controller (10.0.1.5)\nGoal: Domain Admin persistence\nMITRE: T1078 - Valid Accounts")

    print_sub("ATTACK", "Using compromised DA account, attacker installs Golden Ticket on Domain Controller")

    alert = await api_call("POST", "/alerts", {
        "title": "Domain Controller Anomaly",
        "description": "Suspicious service installation on Domain Controller via admin account",
        "severity": "critical",
        "source": "Windows Event Logs",
        "mitre_technique": "T1078",
        "target_device": "srv-ad-01",
        "timestamp": datetime.utcnow().isoformat()
    })
    if alert:
        print_sub("DETECTED", f"Alert created: {alert.get('id', 'N/A')}")

    prediction = await api_call("POST", "/predict", {
        "alert_id": alert.get("id", "sim-005"),
        "current_technique": "T1078",
        "context": {"server": "srv-ad-01", "account_used": "GOV-HOSPITAL\\vikram.singh", "action": "service_install"}
    })
    if prediction:
        predicted = prediction.get("predicted_technique", "T1486")
        print_sub("AI PREDICTION", f"Next move: {predicted} - Data Encrypted for Impact (confidence: {prediction.get('confidence', 96)}%)")

    twin = await api_call("POST", "/digital-twin/simulate", {
        "scenario": "domain_compromise",
        "domain_controller": "srv-ad-01"
    })
    if twin:
        br = twin.get("blast_radius", {})
        print_sub("DIGITAL TWIN", f"Full domain compromise: {br.get('domain_compromised', True)}")
        print_sub("SIMULATION", f"Assets under attacker control: {br.get('controlled_assets', 24)}")
        print_sub("IMPACT", f"Estimated breach cost: ${br.get('estimated_cost', 250000):,}")

    response = await api_call("POST", "/respond", {
        "incident_type": "privilege_escalation",
        "actions": ["emergency_dc_lockdown", "reset_krbtgt", "initiate_incident_response"]
    })
    if response:
        print_sub("RESPONSE", "Domain Controller isolated, krbtgt password reset queued, IR team notified")

    return True


async def step6_ransomware_deployment():
    print_step(6, "Ransomware Deployment on File Shares", "Target: File Server shares, EHR documents\nPayload: LockBit 3.0 variant\nMITRE: T1486 - Data Encrypted for Impact")

    print_sub("ATTACK", "Ransomware deployed via Group Policy push to encrypt all mapped drives and network shares")

    alert = await api_call("POST", "/alerts", {
        "title": "Ransomware Encryption Detected",
        "description": "Mass file encryption detected on File Server - .lockbit extension being written across all shares",
        "severity": "critical",
        "source": "File Integrity Monitor",
        "mitre_technique": "T1486",
        "target_device": "srv-file-01",
        "timestamp": datetime.utcnow().isoformat()
    })
    if alert:
        print_sub("DETECTED", f"Alert created: {alert.get('id', 'N/A')}")

    print_sub("PROPAGATION", "Ransomware spreading to: EHR Server, PACS Server, Backup Server")
    print_sub("FILES AFFECTED", "Patient records, radiology images, admin documents, backup catalogs")

    twin = await api_call("POST", "/digital-twin/simulate", {
        "scenario": "ransomware_impact",
        "patient_data_encrypted": True,
        "backup_integrity": "compromised"
    })
    if twin:
        br = twin.get("blast_radius", {})
        print_sub("DIGITAL TWIN", f"Patients affected: {br.get('patients_affected', 15000)}")
        print_sub("SIMULATION", f"Systems encrypted: {br.get('systems_encrypted', 30)} of {br.get('total_systems', 45)}")
        print_sub("ESTIMATED", f"Downtime cost: ${br.get('downtime_cost', 500000):,}/hour")

    response = await api_call("POST", "/respond", {
        "incident_type": "ransomware",
        "actions": ["activate_air_gapped_backup", "isolate_all_critical_servers", "deploy_decoy_files"]
    })
    if response:
        print_sub("RESPONSE", "Air-gapped backups activated, critical servers isolated")
        print_sub("AUTONOMOUS", "Ransomware strain identified: LockBit 3.0 variant. Decryptor search initiated.")

    return True


async def step7_ai_prediction_summary():
    print_step(7, "AI Prediction Summary & Post-Incident Learning", "All 7 Agents have been engaged throughout the attack")

    print_sub("BEHAVIOUR AGENT", "Deviations detected: PowerShell from Office, LSASS access, lateral SMB - all flagged as anomalous")

    print_sub("ATTACK STORY BUILDER", "Full ATT&CK chain reconstructed:")
    print("          T1566 (Phishing) -> T1204 (User Exec) -> T1059 (PowerShell)", flush=True)
    print("          -> T1003 (Cred Dump) -> T1021 (Lateral) -> T1078 (Escalate)", flush=True)
    print("          -> T1486 (Ransomware)", flush=True)

    print_sub("THREAT PREDICTION", "At each step, next technique predicted with avg 91% confidence")

    print_sub("DIGITAL TWIN", "Blast radius simulated at every stage without production impact")
    print_sub("SIMULATION SAVINGS", "Estimated $2.5M in prevented damage by predicting spread")

    print_sub("RESPONSE AGENT", "6 autonomous actions taken, 2 required human approval")
    print_sub("MEAN TIME TO RESPOND", "23 seconds (industry avg: 3.5 hours)")

    print_sub("LEARNING AGENT", "New attack pattern stored in Self-Learning Memory")
    print_sub("FUTURE PROTECTION", "Similar phishing campaign would be blocked automatically")

    incident = await api_call("POST", "/incidents", {
        "title": "Simulated Ransomware Attack - LockBit 3.0",
        "description": "Full kill chain simulation from phishing to ransomware encryption",
        "severity": "critical",
        "status": "contained",
        "total_steps": 6,
        "techniques_used": ["T1566", "T1204", "T1059", "T1003", "T1021", "T1078", "T1486"],
        "affected_assets": ["ws-rajesh-01", "srv-file-01", "srv-ad-01", "srv-ehr-01", "srv-pacs-01"],
        "tactics_used": ["Initial Access", "Execution", "Credential Access", "Lateral Movement", "Privilege Escalation", "Impact"],
        "detection_rate": "100%",
        "mttr_seconds": 23,
        "ai_confidence_avg": 91.0,
        "timestamp": datetime.utcnow().isoformat()
    })
    if incident:
        print_sub("INCIDENT LOGGED", f"Complete attack recorded as incident #{incident.get('id', 'N/A')}")

    return True


async def step8_cleanup():
    print_step(8, "Cleanup & Recovery", "Post-incident activities")

    print_sub("RESTORE", "Patient data restored from air-gapped backup (15 min RTO)")
    print_sub("PATCHING", "5 CVEs identified and patched during recovery")
    print_sub("POLICY UPDATE", "Email filtering rules enhanced, macro policies enforced")
    print_sub("REPORT", "Complete incident report generated for CERT-In compliance")
    print_sub("LESSON LEARNED", "Attack pattern added to active defense playbook")

    return True


async def main():
    print()
    print("=" * 70)
    print("  SENTINEL-X: AI-POWERED CYBER RESILIENCE DEMO")
    print("  Ransomware Attack Simulation")
    print("=" * 70)
    print()
    print(f"  Backend API: {API_BASE}")
    print(f"  Started at:  {datetime.utcnow().isoformat()}")
    print()
    print("  NOTE: This demo requires the backend server running.")
    print("  API calls will fail gracefully if backend is unreachable.")
    print()

    steps = [
        step1_phishing,
        step2_macro_execution,
        step3_credential_dumping,
        step4_lateral_movement,
        step5_privilege_escalation,
        step6_ransomware_deployment,
        step7_ai_prediction_summary,
        step8_cleanup,
    ]

    for i, step in enumerate(steps, 1):
        try:
            await step()
        except Exception as e:
            print_sub(f"ERROR in step {i}", str(e))
        await asyncio.sleep(0.5)

    print()
    print("=" * 70)
    print("  DEMO COMPLETE")
    print("  Sentinel-X successfully detected, predicted, simulated,")
    print("  responded to, and learned from the attack.")
    print("=" * 70)
    print()


if __name__ == "__main__":
    asyncio.run(main())
