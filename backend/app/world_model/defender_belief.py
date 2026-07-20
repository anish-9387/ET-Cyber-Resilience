from __future__ import annotations

from typing import Any, Dict, List

from app.world_model.entity_state import utcnow


UNCERTAIN_LOWER = 0.25
UNCERTAIN_UPPER = 0.75
LOW_CONFIDENCE_THRESHOLD = 0.6

COLLECTION_BY_ENTITY_TYPE: Dict[str, List[str]] = {
    "server": [
        "LSASS memory snapshot",
        "EDR process tree for the last 4 hours",
        "Windows Security 4624/4672 logon events",
        "Sysmon EventID 1/3/11 export",
    ],
    "user": [
        "Authentication timeline across all IdP sources",
        "Mailbox rule and delegation audit",
        "Conditional access / MFA challenge history",
    ],
    "credential": [
        "Kerberos TGS/TGT issuance audit",
        "Secret-store access log for the credential",
        "Password last-set and replication metadata",
    ],
    "network_device": [
        "NetFlow for the attached segment",
        "Firewall rule change audit",
        "ARP and MAC table snapshot",
    ],
    "iot_device": [
        "DICOM/HL7 session logs",
        "Passive protocol capture on the medical VLAN",
        "Firmware integrity attestation",
    ],
    "ot_device": [
        "S7comm/EtherNet-IP passive capture",
        "PLC program checksum comparison against golden image",
        "Historian tag-write audit",
    ],
    "application": [
        "Application authentication and error logs",
        "WAF request sample for the last hour",
        "Deployed artifact hash verification",
    ],
    "database": [
        "Database audit log for bulk SELECT/EXPORT",
        "Connection source inventory",
        "Backup job integrity report",
    ],
    "department": [
        "Business process owner interview",
        "Departmental asset inventory reconciliation",
    ],
    "deception": [
        "Honeypot interaction transcript",
    ],
}

EVIDENCE_EXPECTATIONS: Dict[str, List[str]] = {
    "server": ["process_execution", "authentication", "network_flow"],
    "user": ["authentication", "email_gateway"],
    "credential": ["authentication", "secret_store_access"],
    "network_device": ["network_flow", "config_change"],
    "iot_device": ["network_flow", "protocol_session"],
    "ot_device": ["protocol_session", "control_logic_integrity"],
    "application": ["application_log", "network_flow"],
    "database": ["query_audit", "authentication"],
    "department": ["business_context"],
    "deception": ["interaction_log"],
}

SOURCE_TO_EVIDENCE_CLASS: Dict[str, str] = {
    "sysmon": "process_execution",
    "windows": "authentication",
    "edr": "process_execution",
    "zeek": "network_flow",
    "netflow": "network_flow",
    "firewall": "network_flow",
    "waf": "application_log",
    "app": "application_log",
    "dicom": "protocol_session",
    "hl7": "protocol_session",
    "scada": "protocol_session",
    "historian": "control_logic_integrity",
    "db_audit": "query_audit",
    "idp": "authentication",
    "vault": "secret_store_access",
    "honeypot": "interaction_log",
}


def _evidence_classes(entity: Any) -> List[str]:
    classes: List[str] = []
    for item in entity.evidence:
        if item.derived:
            continue
        base_source = item.source.split(":")[0].split("[")[0].strip().lower()
        mapped = SOURCE_TO_EVIDENCE_CLASS.get(base_source, base_source)
        if mapped not in classes:
            classes.append(mapped)
    return classes


def _missing_evidence(entity: Any) -> List[str]:
    expected = EVIDENCE_EXPECTATIONS.get(entity.entity_type, [])
    present = set(_evidence_classes(entity))
    missing = [item for item in expected if item not in present]
    if not entity.evidence:
        missing.append("any_direct_telemetry")
    derived_only = entity.evidence and all(item.derived for item in entity.evidence)
    if derived_only:
        missing.append("first_party_confirmation_of_propagated_belief")
    return missing


def _recommended_collection(entity: Any, missing: List[str]) -> List[str]:
    catalogue = COLLECTION_BY_ENTITY_TYPE.get(entity.entity_type, ["Targeted host triage collection"])
    recommendations = list(catalogue[: max(len(missing), 1) + 1])
    segment = entity.attributes.get("segment") or entity.attributes.get("ip")
    if segment and "NetFlow" not in " ".join(recommendations):
        if "/" in str(segment):
            recommendations.append(f"NetFlow for {segment}")
        else:
            octets = str(segment).split(".")
            if len(octets) == 4:
                recommendations.append(f"NetFlow for {octets[0]}.{octets[1]}.{octets[2]}.0/24")
    return recommendations


def _uncertainty_score(entity: Any) -> float:
    distance_from_certainty = 1.0 - abs(entity.p_compromised - 0.5) * 2.0
    return round(distance_from_certainty * (1.0 - entity.confidence), 6)


def assess_defender_belief(model: Any) -> Dict[str, Any]:
    now = utcnow()
    entities = model.all_entities()

    uncertain: List[Dict[str, Any]] = []
    for entity in entities:
        in_band = UNCERTAIN_LOWER <= entity.p_compromised <= UNCERTAIN_UPPER
        low_confidence = entity.confidence < LOW_CONFIDENCE_THRESHOLD
        if not (in_band and low_confidence):
            continue
        missing = _missing_evidence(entity)
        uncertain.append(
            {
                "entity_id": entity.id,
                "name": entity.name,
                "entity_type": entity.entity_type,
                "criticality": entity.criticality,
                "p_compromised": round(entity.p_compromised, 4),
                "confidence": round(entity.confidence, 4),
                "uncertainty_score": _uncertainty_score(entity),
                "evidence_classes_present": _evidence_classes(entity),
                "missing_evidence": missing,
                "recommended_collection": _recommended_collection(entity, missing),
                "why_uncertain": (
                    f"P(compromised)={entity.p_compromised:.3f} sits in the ambiguous band "
                    f"[{UNCERTAIN_LOWER}, {UNCERTAIN_UPPER}] with only "
                    f"{entity.independent_evidence_count()} independent evidence stream(s), "
                    f"yielding confidence {entity.confidence:.3f}."
                ),
            }
        )
    uncertain.sort(key=lambda item: (-item["uncertainty_score"], item["entity_id"]))

    observed_types: Dict[str, Dict[str, int]] = {}
    for entity in entities:
        bucket = observed_types.setdefault(entity.entity_type, {"total": 0, "with_direct_evidence": 0})
        bucket["total"] += 1
        if any(not item.derived for item in entity.evidence):
            bucket["with_direct_evidence"] += 1

    coverage_gaps: List[Dict[str, Any]] = []
    for entity_type, counts in sorted(observed_types.items()):
        if counts["with_direct_evidence"] == 0:
            coverage_gaps.append(
                {
                    "entity_type": entity_type,
                    "entities": counts["total"],
                    "entities_with_direct_evidence": 0,
                    "gap": "no_telemetry",
                    "detail": (
                        f"None of the {counts['total']} '{entity_type}' entities have produced a single "
                        f"first-party observation; Sentinel is blind to this class."
                    ),
                    "recommended_collection": COLLECTION_BY_ENTITY_TYPE.get(entity_type, []),
                }
            )
        elif counts["with_direct_evidence"] < counts["total"] / 2:
            coverage_gaps.append(
                {
                    "entity_type": entity_type,
                    "entities": counts["total"],
                    "entities_with_direct_evidence": counts["with_direct_evidence"],
                    "gap": "partial_telemetry",
                    "detail": (
                        f"Only {counts['with_direct_evidence']} of {counts['total']} '{entity_type}' "
                        f"entities are emitting first-party telemetry."
                    ),
                    "recommended_collection": COLLECTION_BY_ENTITY_TYPE.get(entity_type, []),
                }
            )

    blind_spots: List[Dict[str, Any]] = []
    for entity in entities:
        if entity.confidence >= LOW_CONFIDENCE_THRESHOLD:
            continue
        if entity.risk_weight() < 0.7:
            continue
        if any(not item.derived for item in entity.evidence):
            continue
        blind_spots.append(
            {
                "entity_id": entity.id,
                "name": entity.name,
                "entity_type": entity.entity_type,
                "criticality": entity.criticality,
                "reason": "high-criticality entity with zero first-party telemetry",
                "p_compromised": round(entity.p_compromised, 4),
                "confidence": round(entity.confidence, 4),
                "mission_functions": list(entity.mission_functions),
            }
        )
    blind_spots.sort(key=lambda item: (-item["p_compromised"], item["entity_id"]))

    if entities:
        weight_total = sum(entity.risk_weight() for entity in entities)
        overall_confidence = round(
            sum(entity.confidence * entity.risk_weight() for entity in entities) / weight_total, 4
        ) if weight_total else 0.0
    else:
        overall_confidence = 0.0

    return {
        "generated_at": now.isoformat(),
        "overall_confidence": overall_confidence,
        "confidence_basis": (
            "criticality-weighted mean of per-entity confidence, where per-entity confidence is "
            "1 - exp(-k * effective independent evidence) scaled by evidence agreement"
        ),
        "uncertain_entities": uncertain,
        "uncertain_entity_count": len(uncertain),
        "coverage_gaps": coverage_gaps,
        "blind_spots": blind_spots,
        "entities_with_direct_evidence": sum(
            1 for entity in entities if any(not item.derived for item in entity.evidence)
        ),
        "total_entities": len(entities),
    }
