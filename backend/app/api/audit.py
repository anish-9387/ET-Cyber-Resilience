from fastapi import APIRouter, HTTPException, Query
from typing import Any, Dict, List, Optional

from app.world_model.audit import audit

router = APIRouter()


@router.get("/trail")
async def get_trail(
    limit: int = Query(100, ge=1, le=1000),
    actor: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    target: Optional[str] = Query(None),
    actor_type: Optional[str] = Query(None),
) -> List[Dict[str, Any]]:
    return audit.query(limit=limit, actor=actor, action=action, target=target, actor_type=actor_type)


@router.get("/stats")
async def get_stats() -> Dict[str, Any]:
    return audit.stats()


@router.get("/verify")
async def verify_chain() -> Dict[str, Any]:
    return audit.verify_chain()


@router.get("/trail/{record_id}")
async def get_record(record_id: str) -> Dict[str, Any]:
    record = audit.get(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"audit record '{record_id}' not found")
    return record
