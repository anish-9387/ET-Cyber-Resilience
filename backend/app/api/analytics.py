from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone, timedelta
from app.core.database import get_db
from app.models import Incident, Event, Asset, Agent
from app.core.logger import logger

router = APIRouter()


@router.get("/dashboard")
async def get_dashboard(db: AsyncSession = Depends(get_db)):
    now = datetime.now(timezone.utc)
    last_24h = now - timedelta(hours=24)
    last_7d = now - timedelta(days=7)

    total_incidents = (await db.execute(select(func.count(Incident.id)))).scalar() or 0
    open_incidents = (await db.execute(
        select(func.count(Incident.id)).where(Incident.status.in_(["new", "investigating", "contained"]))
    )).scalar() or 0
    critical_incidents = (await db.execute(
        select(func.count(Incident.id)).where(Incident.severity == "critical")
    )).scalar() or 0
    incidents_24h = (await db.execute(
        select(func.count(Incident.id)).where(Incident.created_at >= last_24h)
    )).scalar() or 0

    total_assets = (await db.execute(select(func.count(Asset.id)))).scalar() or 0
    critical_assets = (await db.execute(
        select(func.count(Asset.id)).where(Asset.criticality == "critical")
    )).scalar() or 0

    total_agents = (await db.execute(select(func.count(Agent.id)))).scalar() or 0
    active_agents = (await db.execute(
        select(func.count(Agent.id)).where(
            Agent.status == "running",
            Agent.last_heartbeat >= last_24h,
        )
    )).scalar() or 0

    total_events_24h = (await db.execute(
        select(func.count(Event.id)).where(Event.created_at >= last_24h)
    )).scalar() or 0

    return {
        "incidents": {
            "total": total_incidents,
            "open": open_incidents,
            "critical": critical_incidents,
            "last_24h": incidents_24h,
        },
        "assets": {
            "total": total_assets,
            "critical": critical_assets,
        },
        "agents": {
            "total": total_agents,
            "active": active_agents,
        },
        "events_last_24h": total_events_24h,
        "timestamp": now.isoformat(),
    }


@router.get("/incidents/trend")
async def incident_trend(
    days: int = Query(7, ge=1, le=90),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    results = await db.execute(
        select(
            func.date_trunc("day", Incident.created_at).label("day"),
            func.count(Incident.id).label("count"),
        )
        .where(Incident.created_at >= start)
        .group_by(text("day"))
        .order_by(text("day"))
    )
    trend_data = [{"date": str(row[0]), "count": row[1]} for row in results.all()]
    return {"days": days, "trend": trend_data}


@router.get("/incidents/by-severity")
async def incidents_by_severity(db: AsyncSession = Depends(get_db)):
    results = await db.execute(
        select(Incident.severity, func.count(Incident.id))
        .group_by(Incident.severity)
    )
    return {str(row[0].value if hasattr(row[0], 'value') else row[0]): row[1] for row in results.all()}


@router.get("/incidents/by-type")
async def incidents_by_type(db: AsyncSession = Depends(get_db)):
    results = await db.execute(
        select(Incident.incident_type, func.count(Incident.id))
        .group_by(Incident.incident_type)
    )
    return {str(row[0].value if hasattr(row[0], 'value') else row[0]): row[1] for row in results.all()}


@router.get("/assets/by-type")
async def assets_by_type(db: AsyncSession = Depends(get_db)):
    results = await db.execute(
        select(Asset.asset_type, func.count(Asset.id))
        .group_by(Asset.asset_type)
    )
    return {str(row[0].value if hasattr(row[0], 'value') else row[0]): row[1] for row in results.all()}


@router.get("/assets/by-criticality")
async def assets_by_criticality(db: AsyncSession = Depends(get_db)):
    results = await db.execute(
        select(Asset.criticality, func.count(Asset.id))
        .group_by(Asset.criticality)
    )
    return {str(row[0].value if hasattr(row[0], 'value') else row[0]): row[1] for row in results.all()}


@router.get("/agents/by-type")
async def agents_by_type(db: AsyncSession = Depends(get_db)):
    results = await db.execute(
        select(Agent.agent_type, func.count(Agent.id))
        .group_by(Agent.agent_type)
    )
    return {str(row[0].value if hasattr(row[0], 'value') else row[0]): row[1] for row in results.all()}


@router.get("/agents/by-status")
async def agents_by_status(db: AsyncSession = Depends(get_db)):
    results = await db.execute(
        select(Agent.status, func.count(Agent.id))
        .group_by(Agent.status)
    )
    return {str(row[0].value if hasattr(row[0], 'value') else row[0]): row[1] for row in results.all()}


@router.get("/mttr")
async def mean_time_to_resolve(
    days: int = Query(30, ge=1, le=365),
    db: AsyncSession = Depends(get_db),
):
    now = datetime.now(timezone.utc)
    start = now - timedelta(days=days)
    results = await db.execute(
        select(
            Incident.severity,
            func.avg(
                func.extract("epoch", Incident.resolved_at - Incident.created_at) / 3600
            ).label("avg_hours"),
        )
        .where(
            Incident.resolved_at.isnot(None),
            Incident.created_at >= start,
        )
        .group_by(Incident.severity)
    )
    mttr_data = {}
    for row in results.all():
        severity = str(row[0].value if hasattr(row[0], 'value') else row[0])
        mttr_data[severity] = round(float(row[1]), 1) if row[1] else 0
    return {"days": days, "mttr_hours": mttr_data, "overall_mttr_hours": round(sum(mttr_data.values()) / max(len(mttr_data), 1), 1)}
