from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from typing import Any, Dict, Optional

from app.core.auth_deps import require_approver
from app.world_model.decision_engine import decision_engine

router = APIRouter()


class ExecuteRequest(BaseModel):
    """Request to execute a response option.

    Deliberately carries NO `approved_by`. Accepting one here let a single
    unauthenticated call both request and approve a red-risk action such as
    `network_isolation`, which collapsed the two-step human gate into one and
    made the approval control decorative. Approval for a gated option must go
    through POST /decision/approve/{execution_id} with a bearer token.
    """

    option_id: str


class ApprovalRequest(BaseModel):
    """Approval decision. The approver identity comes from the bearer token,
    never from the request body - a caller must not be able to name themselves
    as the approver."""

    decision: str = Field("approve", pattern="^(approve|reject)$")
    reason: str = ""


class RollbackRequest(BaseModel):
    actor: str = "decision_engine"


@router.get("/options")
async def get_options(horizon_minutes: int = Query(60, ge=5, le=1440)) -> Dict[str, Any]:
    return decision_engine.options(horizon_minutes)


@router.post("/execute")
async def execute_option(payload: ExecuteRequest) -> Dict[str, Any]:
    # approved_by is intentionally None: execution never self-approves. A gated
    # option returns status 'pending_approval' and must be approved separately.
    result = decision_engine.execute(payload.option_id, None)
    if result.get("error") == "option_not_found":
        raise HTTPException(status_code=404, detail=f"option '{payload.option_id}' not found")
    return result


@router.get("/pending-approvals")
async def pending_approvals() -> Dict[str, Any]:
    pending = decision_engine.pending_approvals()
    return {"count": len(pending), "pending_approvals": pending}


@router.get("/executions")
async def list_executions() -> Dict[str, Any]:
    executions = decision_engine.executions()
    return {"count": len(executions), "executions": executions}


@router.post("/approve/{execution_id}")
async def approve_execution(
    execution_id: str,
    payload: ApprovalRequest,
    approver: Dict[str, Any] = Depends(require_approver),
) -> Dict[str, Any]:
    result = decision_engine.approve(
        execution_id, approver["username"], payload.decision, payload.reason
    )
    if result.get("error") == "execution_not_found":
        raise HTTPException(status_code=404, detail=f"execution '{execution_id}' not found")
    if result.get("error") == "not_pending":
        raise HTTPException(
            status_code=409,
            detail=f"execution '{execution_id}' is '{result['status']}', not pending approval",
        )
    return result


@router.post("/rollback/{execution_id}")
async def rollback_execution(execution_id: str, payload: Optional[RollbackRequest] = None) -> Dict[str, Any]:
    actor = payload.actor if payload else "decision_engine"
    result = decision_engine.rollback(execution_id, actor)
    if result.get("error") == "execution_not_found":
        raise HTTPException(status_code=404, detail=f"execution '{execution_id}' not found")
    if result.get("error") == "not_rollbackable":
        raise HTTPException(
            status_code=409,
            detail=f"execution '{execution_id}' is '{result['status']}' and cannot be rolled back",
        )
    return result
