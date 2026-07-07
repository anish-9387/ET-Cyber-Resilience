from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc
from typing import Optional, List
from app.core.database import get_db
from app.models import Incident, IncidentTimeline
from app.schemas.incidents import (
    IncidentCreate, IncidentUpdate, IncidentResponse, IncidentSummary,
    IncidentTimelineEntry, IncidentSearchParams, IncidentStatus,
    IncidentSeverity, IncidentPriority, IncidentType,
)
from app.core.logger import logger
from datetime import datetime, timezone, timedelta

router = APIRouter()


@router.get("", response_model=List[IncidentSummary])
async def list_incidents(
    status: Optional[IncidentStatus] = Query(None),
    severity: Optional[IncidentSeverity] = Query(None),
    priority: Optional[IncidentPriority] = Query(None),
    incident_type: Optional[IncidentType] = Query(None),
    assigned_to: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    query = select(Incident)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    if priority:
        query = query.where(Incident.priority == priority)
    if incident_type:
        query = query.where(Incident.incident_type == incident_type)
    if assigned_to:
        query = query.where(Incident.assigned_to == assigned_to)
    if search:
        query = query.where(
            Incident.title.ilike(f"%{search}%") | Incident.description.ilike(f"%{search}%")
        )
    query = query.order_by(desc(Incident.created_at))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    incidents = result.scalars().all()
    summaries = []
    now = datetime.now(timezone.utc)
    for inc in incidents:
        age = (now - inc.created_at).total_seconds() / 3600 if inc.created_at else 0
        summaries.append(IncidentSummary(
            id=inc.id,
            title=inc.title,
            status=inc.status,
            severity=inc.severity,
            priority=inc.priority,
            incident_type=inc.incident_type,
            created_at=inc.created_at,
            assigned_to=inc.assigned_to,
            age_hours=round(age, 1),
        ))
    return summaries


@router.get("/{incident_id}", response_model=IncidentResponse)
async def get_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    return incident


@router.post("", response_model=IncidentResponse, status_code=status.HTTP_201_CREATED)
async def create_incident(request: IncidentCreate, db: AsyncSession = Depends(get_db)):
    incident = Incident(
        title=request.title,
        description=request.description,
        incident_type=request.incident_type,
        severity=request.severity,
        priority=request.priority,
        source=request.source,
        affected_assets=request.affected_assets or [],
        mitre_techniques=request.mitre_techniques or [],
        indicators=request.indicators or [],
        assigned_to=request.assigned_to,
        tags=request.tags or [],
    )
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    timeline_entry = IncidentTimeline(
        incident_id=incident.id,
        action="created",
        actor="system",
        description=f"Incident '{incident.title}' created with {incident.severity.value} severity",
    )
    db.add(timeline_entry)
    await db.commit()
    logger.info("Incident created", incident_id=incident.id, title=incident.title, severity=incident.severity.value)
    return incident


@router.put("/{incident_id}", response_model=IncidentResponse)
async def update_incident(incident_id: str, request: IncidentUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    update_data = request.model_dump(exclude_unset=True)
    old_status = incident.status
    for field, value in update_data.items():
        setattr(incident, field, value)
    incident.updated_at = datetime.now(timezone.utc)
    if request.status == IncidentStatus.RESOLVED or request.status == IncidentStatus.CLOSED:
        incident.resolved_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(incident)
    if request.status and request.status != old_status:
        timeline_entry = IncidentTimeline(
            incident_id=incident.id,
            action="status_changed",
            actor="system",
            description=f"Status changed from {old_status.value} to {request.status.value}",
        )
        db.add(timeline_entry)
        await db.commit()
    logger.info("Incident updated", incident_id=incident_id, status=incident.status.value if incident.status else None)
    return incident


@router.delete("/{incident_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_incident(incident_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    await db.delete(incident)
    await db.commit()
    logger.info("Incident deleted", incident_id=incident_id)


@router.get("/{incident_id}/timeline", response_model=List[IncidentTimelineEntry])
async def get_incident_timeline(incident_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(IncidentTimeline)
        .where(IncidentTimeline.incident_id == incident_id)
        .order_by(IncidentTimeline.timestamp)
    )
    entries = result.scalars().all()
    return [
        IncidentTimelineEntry(
            incident_id=e.incident_id,
            action=e.action,
            actor=e.actor,
            description=e.description or "",
            metadata=e.metadata_,
            timestamp=e.timestamp,
        )
        for e in entries
    ]


@router.get("/stats/overview")
async def incident_stats(db: AsyncSession = Depends(get_db)):
    total = await db.execute(select(func.count(Incident.id)))
    total_count = total.scalar() or 0
    by_status = await db.execute(
        select(Incident.status, func.count(Incident.id))
        .group_by(Incident.status)
    )
    by_severity = await db.execute(
        select(Incident.severity, func.count(Incident.id))
        .group_by(Incident.severity)
    )
    by_type = await db.execute(
        select(Incident.incident_type, func.count(Incident.id))
        .group_by(Incident.incident_type)
    )
    now = datetime.now(timezone.utc)
    last_24h = await db.execute(
        select(func.count(Incident.id))
        .where(Incident.created_at >= now - timedelta(hours=24))
    )
    return {
        "total": total_count,
        "last_24h": last_24h.scalar() or 0,
        "by_status": {str(row[0].value if hasattr(row[0], 'value') else row[0]): row[1] for row in by_status.all()},
        "by_severity": {str(row[0].value if hasattr(row[0], 'value') else row[0]): row[1] for row in by_severity.all()},
        "by_type": {str(row[0].value if hasattr(row[0], 'value') else row[0]): row[1] for row in by_type.all()},
    }
