from fastapi import APIRouter, HTTPException
from typing import Any, Dict

from app.world_model import world_model
from app.world_model.mission_impact import (
    MISSION_FUNCTIONS,
    compute_function_impact,
    compute_mission_impact,
)

router = APIRouter()


@router.get("/impact")
async def get_mission_impact() -> Dict[str, Any]:
    return compute_mission_impact(world_model)


@router.get("/functions")
async def list_mission_functions() -> Dict[str, Any]:
    return {
        "count": len(MISSION_FUNCTIONS),
        "functions": [
            {
                "name": name,
                "label": definition["label"],
                "population": definition["population"],
                "safety_critical": definition["safety_critical"],
                "declared_entities": definition["entities"],
            }
            for name, definition in MISSION_FUNCTIONS.items()
        ],
    }


@router.get("/impact/{function_name}")
async def get_function_impact(function_name: str) -> Dict[str, Any]:
    definition = MISSION_FUNCTIONS.get(function_name)
    if definition is None:
        raise HTTPException(status_code=404, detail=f"mission function '{function_name}' not found")
    return compute_function_impact(world_model, function_name, definition)
