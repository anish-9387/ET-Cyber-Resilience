from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional, List
from app.core.database import get_db
from app.models import Agent
from app.schemas.agents import (
    AgentCreate, AgentUpdate, AgentResponse, AgentActionRequest,
    AgentActionResponse, AgentLog, AgentRegistrationResponse, AgentStatus, AgentType,
)
from app.core.logger import logger
from datetime import datetime, timezone

router = APIRouter()


@router.get("", response_model=List[AgentResponse])
async def list_agents(
    status: Optional[AgentStatus] = Query(None),
    agent_type: Optional[AgentType] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    query = select(Agent)
    if status:
        query = query.where(Agent.status == status)
    if agent_type:
        query = query.where(Agent.agent_type == agent_type)
    if search:
        query = query.where(Agent.name.ilike(f"%{search}%"))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    agents = result.scalars().all()
    return agents


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    return agent


@router.post("", response_model=AgentResponse, status_code=status.HTTP_201_CREATED)
async def create_agent(request: AgentCreate, db: AsyncSession = Depends(get_db)):
    agent = Agent(
        name=request.name,
        agent_type=request.agent_type,
        description=request.description,
        config=request.config or {},
        tags=request.tags or [],
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    logger.info("Agent created", agent_id=agent.id, name=agent.name, type=agent.agent_type.value)
    return agent


@router.put("/{agent_id}", response_model=AgentResponse)
async def update_agent(agent_id: str, request: AgentUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    update_data = request.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        setattr(agent, field, value)
    agent.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(agent)
    logger.info("Agent updated", agent_id=agent_id)
    return agent


@router.delete("/{agent_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_agent(agent_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    await db.delete(agent)
    await db.commit()
    logger.info("Agent deleted", agent_id=agent_id)


@router.post("/{agent_id}/heartbeat")
async def agent_heartbeat(agent_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    agent.last_heartbeat = datetime.now(timezone.utc)
    agent.status = AgentStatus.RUNNING
    await db.commit()
    return {"status": "ok", "timestamp": agent.last_heartbeat}


@router.post("/{agent_id}/action", response_model=AgentActionResponse)
async def execute_agent_action(
    agent_id: str,
    request: AgentActionRequest,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Agent).where(Agent.id == agent_id))
    agent = result.scalar_one_or_none()
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Agent not found")
    start = datetime.now(timezone.utc)
    try:
        from app.core.event_bus import event_bus
        await event_bus.publish(f"agent:{agent_id}:action", {
            "action": request.action,
            "params": request.params or {},
        })
        elapsed = int((datetime.now(timezone.utc) - start).total_seconds() * 1000)
        logger.info("Agent action dispatched", agent_id=agent_id, action=request.action)
        return AgentActionResponse(
            agent_id=agent_id,
            action=request.action,
            status="dispatched",
            execution_time_ms=elapsed,
            timestamp=datetime.now(timezone.utc),
        )
    except Exception as e:
        logger.error("Agent action failed", agent_id=agent_id, action=request.action, error=str(e))
        return AgentActionResponse(
            agent_id=agent_id,
            action=request.action,
            status="failed",
            error=str(e),
            execution_time_ms=0,
            timestamp=datetime.now(timezone.utc),
        )


@router.post("/register", response_model=AgentRegistrationResponse)
async def register_agent(request: AgentCreate, db: AsyncSession = Depends(get_db)):
    import secrets
    api_key = secrets.token_urlsafe(32)
    agent = Agent(
        name=request.name,
        agent_type=request.agent_type,
        description=request.description,
        config=request.config or {},
        tags=request.tags or [],
        api_key=api_key,
    )
    db.add(agent)
    await db.commit()
    await db.refresh(agent)
    logger.info("Agent registered", agent_id=agent.id, name=agent.name)
    return AgentRegistrationResponse(
        agent_id=agent.id,
        api_key=api_key,
        status=AgentStatus.IDLE,
        message="Agent registered successfully",
    )
