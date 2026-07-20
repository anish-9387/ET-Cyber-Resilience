from fastapi import APIRouter, Query
from pydantic import BaseModel, Field
from typing import Any, Dict, List, Optional

from app.world_model import world_model
from app.world_model.counterfactual import SUPPORTED_INTERVENTIONS, evaluate_counterfactual
from app.world_model.forecast import generate_futures

router = APIRouter()


class Intervention(BaseModel):
    type: str = Field(..., description=f"one of {SUPPORTED_INTERVENTIONS}")
    target: Optional[str] = None
    params: Dict[str, Any] = Field(default_factory=dict)


class CounterfactualRequest(BaseModel):
    interventions: List[Intervention] = Field(default_factory=list)
    horizon_minutes: int = Field(60, ge=5, le=1440)


@router.get("/futures")
async def get_futures(horizon_minutes: int = Query(60, ge=5, le=1440)) -> Dict[str, Any]:
    return generate_futures(world_model, horizon_minutes)


@router.get("/interventions")
async def list_interventions() -> Dict[str, Any]:
    return {
        "supported": SUPPORTED_INTERVENTIONS,
        "mode": "simulated",
        "integration": "none",
    }


@router.post("/counterfactual")
async def run_counterfactual(payload: CounterfactualRequest) -> Dict[str, Any]:
    interventions = [item.model_dump() for item in payload.interventions]
    return evaluate_counterfactual(world_model, interventions, payload.horizon_minutes)
