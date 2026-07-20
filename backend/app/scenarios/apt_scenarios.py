"""Replayable APT scenarios expressed as raw telemetry.

Every event is a dict in the *native* format of its sensor, so replaying a
scenario exercises the real normalizers in `app.services.event_processor`
rather than a synthetic shortcut. Two keys are added on top of the native
payload and are stripped by the ingest pipeline before normalization:

    offset_seconds : float  seconds from the start of the scenario
    ground_truth   : {"is_malicious": bool, "true_technique": str | None}

`ground_truth` is what the evaluation harness scores detection and attribution
against. Benign events are interleaved deliberately so false-positive rate is
measurable.

Malicious events embed a snake_case `[rule: ...]` tag in their message text.
Real SIEM/Sigma detections carry rule names in exactly this shape, and it is
what `agents.mitre_mapper` keys its technique lookup on.
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

LOCKBIT_HOSPITAL: List[Dict[str, Any]] = [
    {
        "offset_seconds": 0,
        "source_type": "windows",
        "EventID": 4624,
        "TimeCreated": "2026-03-04T07:12:04Z",
        "Computer": "HOSP-WS041",
        "User": "MEDNET\\j.sandoval",
        "Level": 4,
        "Channel": "Security",
        "Message": "An account was successfully logged on. Logon Type 2 (Interactive) from ward terminal.",
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
    {
        "offset_seconds": 45,
        "source_type": "zeek",
        "entity_id": "HOSP-WS041",
        "_path": "conn",
        "uid": "CxT8n21kQ9aB",
        "ts": "2026-03-04T07:12:49Z",
        "id.orig_h": "10.20.14.41",
        "id.orig_p": 51203,
        "id.resp_h": "10.20.5.11",
        "id.resp_p": 443,
        "proto": "tcp",
        "service": "ssl",
        "duration": 12.4,
        "orig_bytes": 8421,
        "resp_bytes": 118234,
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
    {
        "offset_seconds": 900,
        "source_type": "windows",
        "EventID": 4625,
        "TimeCreated": "2026-03-04T07:27:04Z",
        "Computer": "HOSP-VPN01",
        "User": "MEDNET\\administrator",
        "Level": 2,
        "Channel": "Security",
        "Message": "An account failed to log on. 47 failures from 91.219.238.14 in 90 seconds [rule: brute_force]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1110"},
    },
    {
        "offset_seconds": 1260,
        "source_type": "windows",
        "EventID": 4624,
        "TimeCreated": "2026-03-04T07:33:04Z",
        "Computer": "HOSP-VPN01",
        "User": "MEDNET\\svc_backup",
        "Level": 4,
        "Channel": "Security",
        "Message": "Logon Type 10 (RemoteInteractive) from 91.219.238.14 outside approved geography [rule: valid_accounts]",
        "location": "Kaliningrad",
        "ground_truth": {"is_malicious": True, "true_technique": "T1078"},
    },
    {
        "offset_seconds": 1500,
        "source_type": "windows",
        "EventID": 4688,
        "TimeCreated": "2026-03-04T07:37:04Z",
        "Computer": "HOSP-VPN01",
        "User": "MEDNET\\svc_backup",
        "Level": 3,
        "Channel": "Security",
        "Message": "New process created: powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA [rule: powershell]",
        "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA",
        "ground_truth": {"is_malicious": True, "true_technique": "T1059"},
    },
    {
        "offset_seconds": 1680,
        "source_type": "suricata",
        "entity_id": "HOSP-VPN01",
        "timestamp": "2026-03-04T07:40:04Z",
        "event_type": "alert",
        "src_ip": "10.20.9.7",
        "dest_ip": "185.220.101.44",
        "src_port": 49882,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature_id": 2038421,
            "signature": "ET MALWARE LockBit CobaltStrike beacon check-in",
            "category": "A Network Trojan was detected",
            "severity": 1,
        },
        "ground_truth": {"is_malicious": True, "true_technique": "T1071"},
    },
    {
        "offset_seconds": 2100,
        "source_type": "windows",
        "EventID": 4698,
        "TimeCreated": "2026-03-04T07:47:04Z",
        "Computer": "HOSP-VPN01",
        "User": "MEDNET\\svc_backup",
        "Level": 3,
        "Channel": "Security",
        "Message": "A scheduled task was created: \\Microsoft\\Windows\\UpdateOrchestrator\\SysHealth [rule: schtask]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1053"},
    },
    {
        "offset_seconds": 2400,
        "source_type": "wazuh",
        "timestamp": "2026-03-04T07:52:04Z",
        "agent": {"id": "011", "name": "HOSP-VPN01"},
        "rule": {
            "id": "92301",
            "level": 12,
            "description": "Windows Defender real-time protection disabled [rule: disable_av]",
        },
        "full_log": "Set-MpPreference -DisableRealtimeMonitoring $true; sc stop WinDefend [rule: disable_av]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1562"},
    },
    {
        "offset_seconds": 2760,
        "source_type": "windows",
        "EventID": 4656,
        "TimeCreated": "2026-03-04T07:58:04Z",
        "Computer": "HOSP-VPN01",
        "User": "MEDNET\\svc_backup",
        "Level": 2,
        "Channel": "Security",
        "Message": "Handle requested to lsass.exe memory by rundll32.exe comsvcs.dll MiniDump [rule: lsass]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1003"},
    },
    {
        "offset_seconds": 3000,
        "source_type": "windows",
        "EventID": 4624,
        "TimeCreated": "2026-03-04T08:02:04Z",
        "Computer": "HOSP-EMR01",
        "User": "MEDNET\\radiology.tech",
        "Level": 4,
        "Channel": "Security",
        "Message": "An account was successfully logged on. Logon Type 3 from imaging workstation.",
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
    {
        "offset_seconds": 3300,
        "source_type": "windows",
        "EventID": 4688,
        "TimeCreated": "2026-03-04T08:07:04Z",
        "Computer": "HOSP-DC01",
        "User": "MEDNET\\svc_backup",
        "Level": 2,
        "Channel": "Security",
        "Message": "SharpHound collector executed against domain controller [rule: enumeration]",
        "command_line": "SharpHound.exe -c All --zipfilename mednet",
        "ground_truth": {"is_malicious": True, "true_technique": "T1087"},
    },
    {
        "offset_seconds": 3900,
        "source_type": "windows",
        "EventID": 5140,
        "TimeCreated": "2026-03-04T08:17:04Z",
        "Computer": "HOSP-EMR01",
        "User": "MEDNET\\svc_backup",
        "Level": 2,
        "Channel": "Security",
        "Message": "Network share \\\\HOSP-EMR01\\C$ accessed from HOSP-VPN01 [rule: lateral]",
        "resource": "\\\\HOSP-EMR01\\C$",
        "ground_truth": {"is_malicious": True, "true_technique": "T1021"},
    },
    {
        "offset_seconds": 4500,
        "source_type": "linux",
        "hostname": "HOSP-BKP01",
        "timestamp": "2026-03-04T08:27:04Z",
        "type": "auth",
        "user": "svc_backup",
        "severity": "high",
        "message": "Accepted publickey for svc_backup from 10.20.9.7 port 44210 [rule: lateral]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1021"},
    },
    {
        "offset_seconds": 4800,
        "source_type": "wazuh",
        "timestamp": "2026-03-04T08:32:04Z",
        "agent": {"id": "004", "name": "HOSP-BKP01"},
        "rule": {
            "id": "92551",
            "level": 15,
            "description": "Shadow copies and Veeam restore points destroyed [rule: backup_deletion]",
        },
        "full_log": "vssadmin.exe delete shadows /all /quiet && wbadmin delete catalog -quiet [rule: backup_deletion]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1490"},
    },
    {
        "offset_seconds": 5100,
        "source_type": "wazuh",
        "timestamp": "2026-03-04T08:37:04Z",
        "agent": {"id": "004", "name": "HOSP-BKP01"},
        "rule": {
            "id": "92600",
            "level": 15,
            "description": "Mass file modification consistent with ransomware payload [rule: ransomware]",
        },
        "full_log": "18422 files renamed to *.lockbit in 240s on D:\\VeeamRepo [rule: ransomware]",
        "data_size": 184220000,
        "ground_truth": {"is_malicious": True, "true_technique": "T1486"},
    },
    {
        "offset_seconds": 5400,
        "source_type": "wazuh",
        "timestamp": "2026-03-04T08:42:04Z",
        "agent": {"id": "007", "name": "HOSP-EMR01"},
        "rule": {
            "id": "92600",
            "level": 15,
            "description": "Mass file modification consistent with ransomware payload [rule: ransomware]",
        },
        "full_log": "EMR document store encrypted; ransom note RESTORE-MY-FILES.txt written [rule: ransomware]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1486"},
    },
]


APT29_ESPIONAGE: List[Dict[str, Any]] = [
    {
        "offset_seconds": 0,
        "source_type": "windows",
        "EventID": 4624,
        "TimeCreated": "2026-01-08T09:02:11Z",
        "Computer": "CORP-WS112",
        "User": "CORP\\a.whitfield",
        "Level": 4,
        "Channel": "Security",
        "Message": "An account was successfully logged on. Logon Type 2 (Interactive).",
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
    {
        "offset_seconds": 1800,
        "source_type": "wazuh",
        "timestamp": "2026-01-08T09:32:11Z",
        "agent": {"id": "112", "name": "CORP-MAIL01"},
        "rule": {
            "id": "87220",
            "level": 10,
            "description": "Spearphishing attachment delivered to executive mailbox [rule: phishing]",
        },
        "full_log": "sender=hr-benefits@corp-portal-review.com attachment=Q1_Benefits_Review.iso [rule: phishing]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1566"},
    },
    {
        "offset_seconds": 9000,
        "source_type": "windows",
        "EventID": 4688,
        "TimeCreated": "2026-01-08T11:32:11Z",
        "Computer": "CORP-WS112",
        "User": "CORP\\a.whitfield",
        "Level": 3,
        "Channel": "Security",
        "Message": "User mounted ISO and executed embedded LNK launching rundll32 [rule: dropper]",
        "command_line": "rundll32.exe D:\\Benefits\\update.dll,DllRegisterServer",
        "ground_truth": {"is_malicious": True, "true_technique": "T1570"},
    },
    {
        "offset_seconds": 12600,
        "source_type": "zeek",
        "entity_id": "CORP-WS112",
        "_path": "ssl",
        "uid": "CqR44e3mLp2X",
        "ts": "2026-01-08T12:32:11Z",
        "id.orig_h": "10.44.12.112",
        "id.orig_p": 52011,
        "id.resp_h": "104.21.55.190",
        "id.resp_p": 443,
        "proto": "tcp",
        "server_name": "cdn-metrics-eu.workers.dev",
        "ja3": "a0e9f5efd2e2f0b0b0c9f5b7a4d3c211",
        "severity": "medium",
        "ground_truth": {"is_malicious": True, "true_technique": "T1071"},
    },
    {
        "offset_seconds": 86400,
        "source_type": "windows",
        "EventID": 4624,
        "TimeCreated": "2026-01-09T09:02:11Z",
        "Computer": "CORP-WS112",
        "User": "CORP\\a.whitfield",
        "Level": 4,
        "Channel": "Security",
        "Message": "An account was successfully logged on. Logon Type 2 (Interactive).",
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
    {
        "offset_seconds": 90000,
        "source_type": "windows",
        "EventID": 4657,
        "TimeCreated": "2026-01-09T10:12:11Z",
        "Computer": "CORP-WS112",
        "User": "CORP\\a.whitfield",
        "Level": 3,
        "Channel": "Security",
        "Message": "Registry Run key modified: HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\OneDriveSync [rule: persistence]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1547"},
    },
    {
        "offset_seconds": 176400,
        "source_type": "auditd",
        "entity_id": "CORP-JUMP01",
        "timestamp": "2026-01-10T10:12:11Z",
        "type": "EXECVE",
        "serial": "884213",
        "user": "a.whitfield",
        "pid": 22841,
        "comm": "sudo",
        "message": "sudo pkexec policy bypass observed, uid escalated to 0 [rule: privesc]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1068"},
    },
    {
        "offset_seconds": 262800,
        "source_type": "windows",
        "EventID": 4656,
        "TimeCreated": "2026-01-11T10:12:11Z",
        "Computer": "CORP-DC02",
        "User": "CORP\\a.whitfield",
        "Level": 2,
        "Channel": "Security",
        "Message": "DCSync style replication request; lsass credential material accessed [rule: lsass]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1003"},
    },
    {
        "offset_seconds": 266400,
        "source_type": "windows",
        "EventID": 4624,
        "TimeCreated": "2026-01-11T11:12:11Z",
        "Computer": "CORP-FS01",
        "User": "CORP\\backup.operator",
        "Level": 4,
        "Channel": "Security",
        "Message": "Scheduled nightly index job logon. Logon Type 5 (Service).",
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
    {
        "offset_seconds": 349200,
        "source_type": "windows",
        "EventID": 4648,
        "TimeCreated": "2026-01-12T10:12:11Z",
        "Computer": "CORP-FS01",
        "User": "CORP\\svc_sqlagent",
        "Level": 3,
        "Channel": "Security",
        "Message": "Pass-the-ticket authentication to file server over winrm [rule: winrm]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1021"},
    },
    {
        "offset_seconds": 352800,
        "source_type": "linux",
        "hostname": "CORP-FS01",
        "timestamp": "2026-01-12T11:12:11Z",
        "type": "file_access",
        "user": "svc_sqlagent",
        "severity": "medium",
        "message": "Bulk read of 4,182 documents from /srv/legal and /srv/mna staged to /tmp/.cache [rule: collection]",
        "data_size": 2411000000,
        "ground_truth": {"is_malicious": True, "true_technique": "T1005"},
    },
    {
        "offset_seconds": 432000,
        "source_type": "zeek",
        "entity_id": "CORP-FS01",
        "_path": "conn",
        "uid": "CmX99a2bTk7Q",
        "ts": "2026-01-13T09:12:11Z",
        "id.orig_h": "10.44.30.11",
        "id.orig_p": 54120,
        "id.resp_h": "10.44.30.44",
        "id.resp_p": 445,
        "proto": "tcp",
        "service": "smb",
        "orig_bytes": 41200,
        "resp_bytes": 88100,
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
    {
        "offset_seconds": 435600,
        "source_type": "cloudtrail",
        "entity_id": "CORP-FS01",
        "eventID": "c1f2a8d4-91bb-4e21-9a11-77ad9cf0e112",
        "eventTime": "2026-01-13T10:12:11Z",
        "eventName": "PutObject",
        "awsRegion": "eu-central-1",
        "sourceIPAddress": "10.44.30.11",
        "userIdentity": {"arn": "arn:aws:iam::221144556677:user/reporting-sync"},
        "errorCode": None,
        "requestParameters": {"bucketName": "corp-archive-eu", "key": "sync/staged.7z"},
        "description": "2.4 GB archive uploaded to third-party bucket outside baseline [rule: exfiltration]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1048"},
    },
    {
        "offset_seconds": 439200,
        "source_type": "suricata",
        "entity_id": "CORP-FS01",
        "timestamp": "2026-01-13T11:12:11Z",
        "event_type": "alert",
        "src_ip": "10.44.30.11",
        "dest_ip": "185.199.108.153",
        "src_port": 51882,
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "signature_id": 2044112,
            "signature": "ET POLICY large outbound transfer to web service [rule: exfiltration]",
            "category": "Potential Corporate Privacy Violation",
            "severity": 1,
        },
        "data_size": 2411000000,
        "ground_truth": {"is_malicious": True, "true_technique": "T1048"},
    },
    {
        "offset_seconds": 442800,
        "source_type": "windows",
        "EventID": 1102,
        "TimeCreated": "2026-01-13T12:12:11Z",
        "Computer": "CORP-DC02",
        "User": "CORP\\svc_sqlagent",
        "Level": 2,
        "Channel": "Security",
        "Message": "The audit log was cleared to remove operator traces [rule: masquerading]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1036"},
    },
]


OT_WATER_SCADA: List[Dict[str, Any]] = [
    {
        "offset_seconds": 0,
        "source_type": "linux",
        "hostname": "WTR-HIST01",
        "timestamp": "2026-05-19T05:00:00Z",
        "type": "process_poll",
        "user": "historian",
        "severity": "info",
        "message": "Modbus poll cycle completed for 42 tags, all within setpoint tolerance.",
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
    {
        "offset_seconds": 240,
        "source_type": "firewall",
        "entity_id": "WTR-ENG02",
        "timestamp": "2026-05-19T05:04:00Z",
        "action": "allow",
        "protocol": "tcp",
        "src_ip": "172.19.4.12",
        "dst_ip": "172.19.4.1",
        "src_port": 33112,
        "dst_port": 123,
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
    {
        "offset_seconds": 300,
        "source_type": "suricata",
        "entity_id": "WTR-ENG02",
        "timestamp": "2026-05-19T05:05:00Z",
        "event_type": "alert",
        "src_ip": "45.155.205.233",
        "dest_ip": "172.19.4.12",
        "src_port": 48221,
        "dest_port": 8443,
        "proto": "TCP",
        "alert": {
            "signature_id": 2099114,
            "signature": "ET EXPLOIT OT remote-access appliance auth bypass CVE-2026-2117 [rule: exploit]",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
        },
        "ground_truth": {"is_malicious": True, "true_technique": "T1190"},
    },
    {
        "offset_seconds": 900,
        "source_type": "linux",
        "hostname": "WTR-ENG02",
        "timestamp": "2026-05-19T05:15:00Z",
        "type": "webshell_write",
        "user": "www-data",
        "severity": "critical",
        "message": "Unexpected file written to appliance web root: /opt/vendor/www/diag.jsp [rule: persistence]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1505"},
    },
    {
        "offset_seconds": 1500,
        "source_type": "auditd",
        "entity_id": "WTR-ENG02",
        "timestamp": "2026-05-19T05:25:00Z",
        "type": "EXECVE",
        "serial": "551201",
        "user": "www-data",
        "pid": 4412,
        "comm": "bash",
        "message": "Interpreter spawned from web process running vendor diagnostic script [rule: script]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1059"},
    },
    {
        "offset_seconds": 2400,
        "source_type": "zeek",
        "entity_id": "WTR-ENG02",
        "_path": "conn",
        "uid": "CnP12x8bVv3L",
        "ts": "2026-05-19T05:40:00Z",
        "id.orig_h": "172.19.4.12",
        "id.orig_p": 44120,
        "id.resp_h": "172.19.8.0",
        "id.resp_p": 502,
        "proto": "tcp",
        "service": "modbus",
        "severity": "high",
        "note": "Sequential sweep of 172.19.8.0/24 on Modbus port 502 [rule: port_scan]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1046"},
    },
    {
        "offset_seconds": 3000,
        "source_type": "linux",
        "hostname": "WTR-HIST01",
        "timestamp": "2026-05-19T05:50:00Z",
        "type": "process_poll",
        "user": "historian",
        "severity": "info",
        "message": "Modbus poll cycle completed for 42 tags, chlorine dosing nominal at 1.1 mg/L.",
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
    {
        "offset_seconds": 3600,
        "source_type": "suricata",
        "entity_id": "WTR-PLC01",
        "timestamp": "2026-05-19T06:00:00Z",
        "event_type": "alert",
        "src_ip": "172.19.4.12",
        "dest_ip": "172.19.8.21",
        "src_port": 44230,
        "dest_port": 502,
        "proto": "TCP",
        "alert": {
            "signature_id": 2101884,
            "signature": "ET SCADA Modbus unauthorised engineering workstation write [rule: lateral]",
            "category": "Attempted Administrator Privilege Gain",
            "severity": 1,
        },
        "ground_truth": {"is_malicious": True, "true_technique": "T1021"},
    },
    {
        "offset_seconds": 4200,
        "source_type": "linux",
        "hostname": "WTR-HMI01",
        "timestamp": "2026-05-19T06:10:00Z",
        "type": "credential_use",
        "user": "engineer",
        "severity": "high",
        "message": "Vendor default engineering credential reused from remote appliance [rule: compromised_account]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1078"},
    },
    {
        "offset_seconds": 4800,
        "source_type": "wazuh",
        "timestamp": "2026-05-19T06:20:00Z",
        "agent": {"id": "301", "name": "WTR-PLC01"},
        "rule": {
            "id": "94110",
            "level": 13,
            "description": "PLC ladder logic download outside maintenance window [rule: tool_transfer]",
        },
        "full_log": "Function code 0x5A program download to slave 21 from 172.19.4.12 [rule: tool_transfer]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1570"},
    },
    {
        "offset_seconds": 5400,
        "source_type": "wazuh",
        "timestamp": "2026-05-19T06:30:00Z",
        "agent": {"id": "302", "name": "WTR-HMI01"},
        "rule": {
            "id": "94150",
            "level": 14,
            "description": "HMI alarm suppression and setpoint display spoofing [rule: masquerading]",
        },
        "full_log": "Alarm bank 3 muted; displayed chlorine value pinned to 1.1 mg/L [rule: masquerading]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1036"},
    },
    {
        "offset_seconds": 6000,
        "source_type": "linux",
        "hostname": "WTR-HIST01",
        "timestamp": "2026-05-19T06:40:00Z",
        "type": "tag_write",
        "user": "engineer",
        "severity": "critical",
        "message": "Chlorine dosing setpoint driven from 1.1 to 11.4 mg/L on pump skid 2 [rule: data_destruction]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1485"},
    },
    {
        "offset_seconds": 6600,
        "source_type": "wazuh",
        "timestamp": "2026-05-19T06:50:00Z",
        "agent": {"id": "303", "name": "WTR-RTU03"},
        "rule": {
            "id": "94180",
            "level": 15,
            "description": "Safety interlock bypassed on treatment train, RTU unresponsive [rule: wiper]",
        },
        "full_log": "Interlock coil forced OFF; RTU03 firmware region overwritten [rule: wiper]",
        "ground_truth": {"is_malicious": True, "true_technique": "T1485"},
    },
    {
        "offset_seconds": 7200,
        "source_type": "linux",
        "hostname": "WTR-HIST01",
        "timestamp": "2026-05-19T07:00:00Z",
        "type": "process_poll",
        "user": "historian",
        "severity": "info",
        "message": "Poll cycle completed for 39 tags, 3 tags reporting stale values.",
        "ground_truth": {"is_malicious": False, "true_technique": None},
    },
]


SCENARIOS: Dict[str, Dict[str, Any]] = {
    "lockbit_hospital": {
        "id": "lockbit_hospital",
        "name": "LockBit Ransomware - Regional Hospital",
        "description": (
            "VPN credential brute force into a hospital network, Cobalt Strike beacon, "
            "defence impairment and credential theft, lateral movement to the EMR and "
            "backup servers, ending in Veeam repository destruction and mass encryption."
        ),
        "actor": "LockBit affiliate",
        "target_environment": "hospital",
        "terminal_objective": "T1486",
        "duration_seconds": LOCKBIT_HOSPITAL[-1]["offset_seconds"],
        "events": LOCKBIT_HOSPITAL,
    },
    "apt29_espionage": {
        "id": "apt29_espionage",
        "name": "APT29 - Slow Espionage and Data Exfiltration",
        "description": (
            "Spearphishing ISO delivery, low-and-slow C2 over a CDN-fronted channel, "
            "registry persistence, pkexec privilege escalation, DCSync credential access, "
            "document staging on the file server and exfiltration to cloud storage."
        ),
        "actor": "APT29 (Cozy Bear)",
        "target_environment": "corporate",
        "terminal_objective": "T1048",
        "duration_seconds": APT29_ESPIONAGE[-1]["offset_seconds"],
        "events": APT29_ESPIONAGE,
    },
    "ot_water_scada": {
        "id": "ot_water_scada",
        "name": "OT/SCADA Attack - Water Treatment Plant",
        "description": (
            "Exploitation of an internet-facing OT remote-access appliance, web shell "
            "persistence, Modbus reconnaissance across the process network, unauthorised "
            "ladder logic download, HMI alarm suppression and a chlorine overdose with "
            "safety interlocks bypassed."
        ),
        "actor": "OT-focused intrusion set",
        "target_environment": "water_utility",
        "terminal_objective": "T1485",
        "duration_seconds": OT_WATER_SCADA[-1]["offset_seconds"],
        "events": OT_WATER_SCADA,
    },
}


#: Event keys that carry the sensor's own timestamp, per source type.
TIMESTAMP_KEYS = ("TimeCreated", "ts", "timestamp", "eventTime")


def _parse(value: str) -> Optional[datetime]:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def rebase_events(events: List[Dict[str, Any]], anchor: datetime) -> List[Dict[str, Any]]:
    """Shift a scenario's fixed wall-clock timestamps so it ends at `anchor`.

    The scenario bodies are authored against fixed dates. Replaying one months
    later fed the world model evidence that was already months old, and since
    evidence is weighted by `decay_weight` on a 6h half-life, every observation
    arrived with a weight of ~0: beliefs never moved off their priors, no entity
    ever crossed the compromise threshold, and every downstream consumer
    (objective scoring, forecasting, mission impact) saw an empty picture.

    Rebasing preserves the scenario's internal spacing exactly - only the origin
    moves - so replay behaves like live telemetry. `ground_truth` labels and the
    static SCENARIOS bodies are untouched.
    """
    timestamps = [
        parsed
        for event in events
        for key in TIMESTAMP_KEYS
        if key in event and (parsed := _parse(event[key])) is not None
    ]
    if not timestamps:
        return [dict(event) for event in events]

    shift = anchor - max(timestamps)
    rebased: List[Dict[str, Any]] = []
    for event in events:
        item = dict(event)
        for key in TIMESTAMP_KEYS:
            if key not in item:
                continue
            parsed = _parse(item[key])
            if parsed is None:
                continue
            item[key] = (parsed + shift).strftime("%Y-%m-%dT%H:%M:%SZ")
        rebased.append(item)
    return rebased


def get_scenario(scenario_id: str, anchor: Optional[datetime] = None) -> Dict[str, Any]:
    """Return a scenario with its telemetry clock rebased onto the present.

    Pass an explicit `anchor` to pin the timeline (tests, reproducible runs);
    it defaults to now, so the final event lands at replay time.
    """
    if scenario_id not in SCENARIOS:
        raise KeyError(f"Unknown scenario: {scenario_id}")
    scenario = SCENARIOS[scenario_id]
    anchor = anchor or datetime.now(timezone.utc)
    return {**scenario, "events": rebase_events(scenario["events"], anchor), "anchored_at": anchor.isoformat()}


def list_scenarios() -> List[Dict[str, Any]]:
    return [
        {
            "id": s["id"],
            "name": s["name"],
            "description": s["description"],
            "actor": s["actor"],
            "target_environment": s["target_environment"],
            "terminal_objective": s["terminal_objective"],
            "event_count": len(s["events"]),
            "malicious_events": len([e for e in s["events"] if e["ground_truth"]["is_malicious"]]),
            "benign_events": len([e for e in s["events"] if not e["ground_truth"]["is_malicious"]]),
            "duration_seconds": s["duration_seconds"],
            "techniques": sorted({
                e["ground_truth"]["true_technique"]
                for e in s["events"]
                if e["ground_truth"]["true_technique"]
            }),
        }
        for s in SCENARIOS.values()
    ]


def labeled_events(scenario_id: str = None) -> List[Dict[str, Any]]:
    """Flat list of (event, label) pairs for the evaluation harness."""
    targets = [SCENARIOS[scenario_id]] if scenario_id else list(SCENARIOS.values())
    return [
        {"scenario_id": s["id"], "event": e, "ground_truth": e["ground_truth"]}
        for s in targets
        for e in s["events"]
    ]
