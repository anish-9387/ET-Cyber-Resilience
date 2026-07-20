from __future__ import annotations

from typing import Any, Dict, List, Optional

from app.world_model.entity_state import criticality_weight, utcnow


MISSION_FUNCTIONS: Dict[str, Dict[str, Any]] = {
    "patient_care": {
        "label": "Inpatient Care Delivery",
        "population": 1200,
        "safety_critical": True,
        "entities": [
            "srv-ehr-01", "db-ehr-prod", "app-ehr", "srv-ad-01", "sw-core-01",
            "iot-pump-01", "iot-monitor-01", "ot-hvac-01", "app-dns",
        ],
    },
    "emergency_response": {
        "label": "Emergency Department Operations",
        "population": 400,
        "safety_critical": True,
        "entities": [
            "srv-ehr-01", "app-ehr", "iot-ct-01", "iot-pump-01", "iot-monitor-01",
            "srv-ad-01", "sw-core-01", "ot-ups-01",
        ],
    },
    "diagnostics": {
        "label": "Imaging and Diagnostics",
        "population": 800,
        "safety_critical": False,
        "entities": [
            "srv-pacs-01", "db-pacs-archive", "app-pacs", "iot-mri-01",
            "iot-ct-01", "iot-xray-01", "sw-access-01",
        ],
    },
    "records_availability": {
        "label": "Clinical Records Availability and Recoverability",
        "population": 15000,
        "safety_critical": False,
        "entities": [
            "srv-backup-01", "db-ehr-prod", "db-pacs-archive", "srv-file-01",
            "srv-db-01", "srv-ad-01", "db-ad", "cred-backup-admin",
        ],
    },
    "power_supply": {
        "label": "Hospital Power Continuity",
        "population": 15000,
        "safety_critical": True,
        "entities": [
            "ot-plc-power-01", "ot-ups-01", "ot-hmi-01", "ot-historian-01", "sw-ot-01",
        ],
    },
    "water_treatment": {
        "label": "Water Treatment and Sanitation",
        "population": 15000,
        "safety_critical": True,
        "entities": [
            "ot-plc-water-01", "ot-hmi-01", "ot-historian-01", "sw-ot-01",
        ],
    },
}

SAFETY_RISK_LEVELS = [
    (0.05, "none"),
    (0.20, "low"),
    (0.45, "elevated"),
    (0.70, "high"),
]


def _safety_risk(degradation: float, safety_critical: bool) -> str:
    level = "catastrophic"
    for threshold, label in SAFETY_RISK_LEVELS:
        if degradation < threshold:
            level = label
            break
    if not safety_critical:
        downgrade = {"catastrophic": "high", "high": "elevated", "elevated": "low", "low": "none", "none": "none"}
        return downgrade[level]
    return level


def _entity_ids_for(function_name: str, definition: Dict[str, Any], model: Any) -> List[str]:
    declared = [entity_id for entity_id in definition["entities"] if model.get_entity(entity_id)]
    tagged = [
        entity.id
        for entity in model.all_entities()
        if function_name in entity.mission_functions and entity.id not in declared
    ]
    return declared + sorted(tagged)


def compute_function_impact(
    model: Any,
    function_name: str,
    definition: Dict[str, Any],
    overrides: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    overrides = overrides or {}
    entity_ids = _entity_ids_for(function_name, definition, model)
    dependents: List[Dict[str, Any]] = []
    numerator = 0.0
    denominator = 0.0

    for entity_id in entity_ids:
        entity = model.get_entity(entity_id)
        if entity is None:
            continue
        weight = criticality_weight(entity.criticality)
        note = None
        effective_p = entity.p_compromised
        if entity.isolated:
            effective_p = max(effective_p, 0.6)
            note = "isolated_entity_counted_as_unavailable"
        if entity_id in overrides:
            effective_p = max(effective_p, overrides[entity_id])
            note = "projected_compromise_override"
        numerator += weight * effective_p
        denominator += weight
        dependents.append(
            {
                "entity_id": entity.id,
                "name": entity.name,
                "entity_type": entity.entity_type,
                "criticality": entity.criticality,
                "p_compromised": round(entity.p_compromised, 4),
                "contribution_weight": round(weight, 4),
                "note": note,
            }
        )

    degradation = round(numerator / denominator, 6) if denominator else 0.0
    availability = round(max(1.0 - degradation, 0.0), 6)
    population_affected = int(round(definition["population"] * degradation))

    return {
        "name": function_name,
        "label": definition["label"],
        "availability": availability,
        "degradation": degradation,
        "dependent_entities": [item["entity_id"] for item in dependents],
        "dependent_entity_detail": dependents,
        "population_affected": population_affected,
        "population_total": definition["population"],
        "safety_critical": definition["safety_critical"],
        "safety_risk": _safety_risk(degradation, definition["safety_critical"]),
        "method": "criticality-weighted mean of dependent-entity P(compromised); availability = 1 - degradation",
    }


def compute_mission_impact(model: Any, overrides: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    functions = [
        compute_function_impact(model, name, definition, overrides)
        for name, definition in MISSION_FUNCTIONS.items()
    ]

    safety_weight = {"none": 0.0, "low": 0.25, "elevated": 0.5, "high": 0.8, "catastrophic": 1.0}
    weighted_total = 0.0
    weight_sum = 0.0
    for function in functions:
        weight = 1.5 if function["safety_critical"] else 1.0
        weighted_total += weight * function["degradation"]
        weight_sum += weight

    overall = round(weighted_total / weight_sum, 6) if weight_sum else 0.0
    worst = max(functions, key=lambda item: (item["degradation"], item["name"])) if functions else None

    return {
        "generated_at": utcnow().isoformat(),
        "functions": sorted(functions, key=lambda item: (-item["degradation"], item["name"])),
        "overall_mission_risk": overall,
        "population_affected_total": sum(function["population_affected"] for function in functions),
        "worst_affected_function": worst["name"] if worst else None,
        "highest_safety_risk": max(
            (function["safety_risk"] for function in functions),
            key=lambda label: safety_weight.get(label, 0.0),
            default="none",
        ),
        "safety_critical_functions_degraded": [
            function["name"]
            for function in functions
            if function["safety_critical"] and function["degradation"] >= 0.2
        ],
    }


def mission_functions_for_entity(entity_id: str) -> List[str]:
    return [
        name
        for name, definition in MISSION_FUNCTIONS.items()
        if entity_id in definition["entities"]
    ]
