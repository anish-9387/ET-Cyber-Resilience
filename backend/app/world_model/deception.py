from __future__ import annotations

from typing import Any, Dict, List, Optional
import hashlib

from app.core.logger import logger
from app.world_model.audit import audit
from app.world_model.entity_state import criticality_weight, utcnow


ASSET_TEMPLATES: Dict[str, Dict[str, Any]] = {
    "fake_credentials": {
        "entity_type": "credential",
        "name_prefix": "Decoy Credential",
        "criticality": "high",
        "lure_value": 0.8,
        "attach_relations": [
            {"type": "grants_access_to", "direction": "out"},
            {"type": "has_credential", "direction": "in"},
        ],
        "detection_signal": "Any authentication attempt with this credential is a true positive by construction",
        "attributes": {
            "credential_type": "password",
            "username": "svc_backup_legacy",
            "strength": "weak",
            "stored_securely": False,
            "planted": True,
        },
    },
    "honeypot_server": {
        "entity_type": "server",
        "name_prefix": "Honeypot Server",
        "criticality": "high",
        "lure_value": 0.9,
        "attach_relations": [
            {"type": "connected_to", "direction": "out"},
            {"type": "authenticates_to", "direction": "out"},
        ],
        "detection_signal": "Any inbound session to this host is unauthorised by definition",
        "attributes": {
            "role": "File Server",
            "os": "Windows Server 2022",
            "advertised_shares": ["\\\\BACKUP-ARCHIVE\\finance", "\\\\BACKUP-ARCHIVE\\patients"],
            "planted": True,
        },
    },
    "fake_plc": {
        "entity_type": "ot_device",
        "name_prefix": "Decoy PLC",
        "criticality": "critical",
        "lure_value": 0.95,
        "attach_relations": [
            {"type": "connected_to", "direction": "out"},
            {"type": "controls", "direction": "in"},
        ],
        "detection_signal": "Any S7comm/EtherNet-IP write to this device indicates OT-targeting intent",
        "attributes": {
            "device_type": "PLC",
            "vendor": "Siemens S7-1200 (emulated)",
            "protocol": "S7comm",
            "purdue_level": 1,
            "planted": True,
        },
    },
    "decoy_documents": {
        "entity_type": "application",
        "name_prefix": "Decoy Document Set",
        "criticality": "medium",
        "lure_value": 0.6,
        "attach_relations": [
            {"type": "runs_on", "direction": "out"},
            {"type": "depends_on", "direction": "in"},
        ],
        "detection_signal": "Opening or exfiltrating these canary documents beacons on access",
        "attributes": {
            "document_class": "patient_records_export",
            "canary_tokens": True,
            "planted": True,
        },
    },
}


def _assets_store(model: Any) -> List[Dict[str, Any]]:
    if not hasattr(model, "deception_assets"):
        setattr(model, "deception_assets", [])
    return getattr(model, "deception_assets")


def _asset_id(asset_type: str, near_entity: str, ordinal: int) -> str:
    digest = hashlib.sha1(f"{asset_type}|{near_entity}|{ordinal}".encode("utf-8")).hexdigest()[:8]
    return f"decoy-{asset_type.replace('_', '-')}-{ordinal:02d}-{digest}"


def select_placement(model: Any, asset_type: str) -> Optional[str]:
    template = ASSET_TEMPLATES.get(asset_type)
    if not template:
        return None
    best: Optional[tuple] = None
    for entity in model.all_entities():
        if entity.is_deception:
            continue
        degree = len(model.adjacency.get(entity.id, []))
        score = criticality_weight(entity.criticality) * 2.0 + degree * 0.08 + entity.p_compromised
        if asset_type == "fake_plc" and entity.entity_type != "ot_device":
            score -= 1.5
        if asset_type == "fake_credentials" and entity.entity_type not in {"server", "user"}:
            score -= 0.8
        if best is None or score > best[0] or (score == best[0] and entity.id < best[1]):
            best = (score, entity.id)
    return best[1] if best else None


def deploy_asset(
    model: Any,
    asset_type: str,
    near_entity: Optional[str] = None,
    simulated: bool = True,
    deployed_by: str = "deception_engine",
) -> Dict[str, Any]:
    template = ASSET_TEMPLATES.get(asset_type)
    if template is None:
        return {
            "deployed": False,
            "mode": "simulated" if simulated else "unknown",
            "integration": "none",
            "note": f"unknown asset_type '{asset_type}'; supported: {sorted(ASSET_TEMPLATES)}",
        }

    anchor_id = near_entity or select_placement(model, asset_type)
    anchor = model.get_entity(anchor_id) if anchor_id else None
    if anchor is None:
        return {
            "deployed": False,
            "mode": "simulated" if simulated else "unknown",
            "integration": "none",
            "note": f"placement anchor '{near_entity}' not found in the world model",
        }

    store = _assets_store(model)
    ordinal = len(store) + 1
    asset_id = _asset_id(asset_type, anchor.id, ordinal)
    entity = model.add_entity(
        id=asset_id,
        name=f"{template['name_prefix']} near {anchor.name}",
        entity_type=template["entity_type"],
        criticality=template["criticality"],
        mission_functions=[],
        attributes={
            **template["attributes"],
            "deception": True,
            "anchor_entity": anchor.id,
            "lure_value": template["lure_value"],
            "mode": "simulated" if simulated else "deployed",
            "integration": "none",
        },
        prior=0.0001,
        tags=["deception", asset_type],
        is_deception=True,
    )
    entity.is_deception = True

    created_relations: List[Dict[str, Any]] = []
    for spec in template["attach_relations"]:
        if spec["direction"] == "out":
            relation = model.add_relation(asset_id, anchor.id, spec["type"], {"deception": True})
        else:
            relation = model.add_relation(anchor.id, asset_id, spec["type"], {"deception": True})
        if relation:
            created_relations.append(relation.to_dict())

    for neighbor in model.neighbors(anchor.id):
        if neighbor["id"] == asset_id or neighbor["entity_type"] == "department":
            continue
        relation = model.add_relation(asset_id, neighbor["id"], "lures", {"deception": True})
        if relation:
            created_relations.append(relation.to_dict())

    record = {
        "asset_id": asset_id,
        "asset_type": asset_type,
        "name": entity.name,
        "entity_type": template["entity_type"],
        "criticality": template["criticality"],
        "near_entity": anchor.id,
        "near_entity_name": anchor.name,
        "lure_value": template["lure_value"],
        "detection_signal": template["detection_signal"],
        "relations": created_relations,
        "deployed_at": utcnow().isoformat(),
        "deployed_by": deployed_by,
        "deployed": True,
        "mode": "simulated",
        "integration": "none",
        "note": (
            f"{template['name_prefix']} registered as a live world-model entity adjacent to "
            f"{anchor.name}; forecasts and counterfactuals now route through it. "
            f"No real host, credential or PLC was provisioned - this is a simulated asset."
        ),
        "interactions": [],
    }
    store.append(record)
    logger.info(
        "deception_asset_deployed",
        asset_id=asset_id,
        asset_type=asset_type,
        near_entity=anchor.id,
        mode="simulated",
    )
    return record


class DeceptionManager:
    def __init__(self) -> None:
        self._model = None

    def bind(self, model: Any) -> None:
        self._model = model

    @property
    def model(self) -> Any:
        if self._model is None:
            from app.world_model.model import world_model

            self._model = world_model
        return self._model

    def asset_types(self) -> List[Dict[str, Any]]:
        return [
            {
                "asset_type": asset_type,
                "entity_type": template["entity_type"],
                "criticality": template["criticality"],
                "lure_value": template["lure_value"],
                "detection_signal": template["detection_signal"],
            }
            for asset_type, template in sorted(ASSET_TEMPLATES.items())
        ]

    def assets(self) -> List[Dict[str, Any]]:
        model = self.model
        store = _assets_store(model)
        enriched: List[Dict[str, Any]] = []
        for record in store:
            entity = model.get_entity(record["asset_id"])
            enriched.append(
                {
                    **record,
                    "current_p_compromised": round(entity.p_compromised, 6) if entity else None,
                    "interaction_count": len(record.get("interactions", [])),
                    "triggered": bool(entity and entity.evidence),
                }
            )
        return enriched

    def deploy(self, asset_type: str, near_entity: Optional[str] = None, actor: str = "deception_engine") -> Dict[str, Any]:
        model = self.model
        result = deploy_asset(model, asset_type, near_entity, simulated=True, deployed_by=actor)
        audit.record(
            actor=actor,
            actor_type="ai_agent" if actor == "deception_engine" else "human",
            action="deploy_deception",
            target=result.get("asset_id") or (near_entity or "unresolved"),
            decision=(
                f"deploy simulated {asset_type} adjacent to {result.get('near_entity_name', near_entity)}"
                if result.get("deployed")
                else f"declined to deploy {asset_type}"
            ),
            confidence=result.get("lure_value", 0.0) if result.get("deployed") else 0.0,
            evidence=[{"anchor": result.get("near_entity"), "relations": result.get("relations", [])}],
            reasoning=result.get("note", ""),
            alternatives_considered=[
                {"asset_type": item["asset_type"], "lure_value": item["lure_value"]}
                for item in self.asset_types()
                if item["asset_type"] != asset_type
            ],
            rollback_available=True,
            outcome="simulated_deployment" if result.get("deployed") else "not_deployed",
        )
        return result

    def record_interaction(self, asset_id: str, description: str, source: str) -> Optional[Dict[str, Any]]:
        for record in _assets_store(self.model):
            if record["asset_id"] == asset_id:
                interaction = {
                    "timestamp": utcnow().isoformat(),
                    "description": description,
                    "source": source,
                }
                record.setdefault("interactions", []).append(interaction)
                return interaction
        return None


deception_manager = DeceptionManager()
