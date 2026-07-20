from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from typing import Any, Dict, Optional

from app.world_model import world_model
from app.world_model.deception import ASSET_TEMPLATES, deception_manager

router = APIRouter()


class DeployRequest(BaseModel):
    asset_type: str
    near_entity: Optional[str] = None
    actor: str = "deception_engine"


@router.get("/assets")
async def list_assets() -> Dict[str, Any]:
    deception_manager.bind(world_model)
    assets = deception_manager.assets()
    return {
        "count": len(assets),
        "mode": "simulated",
        "integration": "none",
        "available_asset_types": deception_manager.asset_types(),
        "assets": assets,
    }


@router.post("/deploy")
async def deploy_asset(payload: DeployRequest) -> Dict[str, Any]:
    if payload.asset_type not in ASSET_TEMPLATES:
        raise HTTPException(
            status_code=400,
            detail=f"unknown asset_type '{payload.asset_type}'; supported: {sorted(ASSET_TEMPLATES)}",
        )
    deception_manager.bind(world_model)
    result = deception_manager.deploy(payload.asset_type, payload.near_entity, payload.actor)
    if not result.get("deployed"):
        raise HTTPException(status_code=400, detail=result.get("note", "deployment failed"))
    return result
