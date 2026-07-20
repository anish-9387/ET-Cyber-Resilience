from fastapi import APIRouter, HTTPException, Query
from typing import Any, Dict, List, Optional

from app.core.logger import logger
from app.world_model import world_model
from app.world_model.entity_state import utcnow

router = APIRouter()


@router.get("/state")
async def get_state() -> Dict[str, Any]:
    return world_model.snapshot()


@router.get("/entities")
async def list_entities(
    entity_type: Optional[str] = Query(None),
    min_compromise: float = Query(0.0, ge=0.0, le=1.0),
) -> List[Dict[str, Any]]:
    now = utcnow()
    results = []
    for entity in world_model.all_entities():
        if entity_type and entity.entity_type != entity_type:
            continue
        if entity.p_compromised < min_compromise:
            continue
        results.append(entity.to_dict(now=now))
    return results


@router.get("/entities/{entity_id}")
async def get_entity(entity_id: str) -> Dict[str, Any]:
    entity = world_model.get_entity(entity_id)
    if entity is None:
        raise HTTPException(status_code=404, detail=f"entity '{entity_id}' not found")
    now = utcnow()
    payload = entity.to_dict(include_evidence=True, now=now)
    payload["neighbors"] = world_model.neighbors(entity_id)
    payload["mission_impact_membership"] = list(entity.mission_functions)
    payload["distance_from_compromised"] = world_model.distance_from_compromised(entity_id)
    return payload


@router.get("/graph")
async def get_graph() -> Dict[str, Any]:
    return world_model.graph()


@router.get("/attacker-belief")
async def get_attacker_belief() -> Dict[str, Any]:
    return world_model.attacker_belief()


@router.get("/defender-belief")
async def get_defender_belief() -> Dict[str, Any]:
    return world_model.defender_belief()


@router.get("/observations")
async def get_observations(limit: int = Query(100, ge=1, le=1000)) -> Dict[str, Any]:
    log = world_model.observation_log[-limit:]
    return {
        "count": len(log),
        "total": len(world_model.observation_log),
        "mttd_minutes": world_model.mttd_minutes(),
        "observations": list(reversed(log)),
    }


@router.post("/reset")
async def reset_world_model() -> Dict[str, Any]:
    world_model.reset()
    logger.info("world_model_reset_via_api")
    return {
        "status": "reset",
        "snapshot_id": world_model.snapshot_id(),
        "entity_count": len(world_model.entities),
        "relation_count": len(world_model.relations),
        "seed": world_model.seed_metadata,
    }
