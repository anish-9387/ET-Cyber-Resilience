from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field
from app.core.database import get_db
from app.models import Event, Incident
from app.schemas.events import (
    EventCreate, EventResponse, EventSearchParams,
    EventProcessResult, EventStats, EventSeverity, EventCategory,
)
from app.schemas.incidents import IncidentCreate, IncidentResponse, IncidentSeverity as IncSeverity, IncidentPriority, IncidentType
from app.core.logger import logger
from app.utils.mitre import mitre_manager
from datetime import datetime, timezone, timedelta

router = APIRouter()


class ThreatIntelFeed(BaseModel):
    feed_name: str
    feed_type: str = Field(default="stix", description="STIX, MISP, OpenCTI, custom")
    indicator_type: str = Field(default="ip", description="ip, domain, url, hash, email")
    indicators: List[str]
    confidence: float = Field(default=0.5, ge=0, le=1.0)
    source: str = "external"
    tags: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class ThreatIntelResponse(BaseModel):
    ingested: int
    skipped: int
    new_indicators: List[str]
    matched_incidents: int


class IoCSearchParams(BaseModel):
    indicator: Optional[str] = None
    indicator_type: Optional[str] = None
    source: Optional[str] = None
    min_confidence: Optional[float] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=500)


@router.post("/feeds/ingest", response_model=ThreatIntelResponse)
async def ingest_threat_feed(feed: ThreatIntelFeed, db: AsyncSession = Depends(get_db)):
    ingested = 0
    skipped = 0
    new_indicators = []
    matched_incidents = 0
    for indicator in feed.indicators:
        existing = await db.execute(
            select(Event).where(
                Event.event_type == "threat_intel",
                Event.raw_data["indicator"].as_string() == indicator,
            )
        )
        if existing.scalar_one_or_none():
            skipped += 1
            continue
        event = Event(
            event_type="threat_intel",
            category=EventCategory.THREAT,
            severity=EventSeverity.HIGH if feed.confidence > 0.7 else EventSeverity.MEDIUM,
            source=feed.source or feed.feed_name,
            title=f"Threat indicator: {indicator}",
            description=f"{feed.indicator_type.upper()} indicator from {feed.feed_name}",
            raw_data={
                "indicator": indicator,
                "indicator_type": feed.indicator_type,
                "confidence": feed.confidence,
                "feed_name": feed.feed_name,
                "feed_type": feed.feed_type,
            },
            tags=feed.tags or [],
        )
        db.add(event)
        ingested += 1
        new_indicators.append(indicator)
    await db.commit()
    if ingested > 0:
        matching = await db.execute(
            select(Incident).where(
                Incident.indicators.overlap(new_indicators),
                Incident.status.notin_(["resolved", "closed", "false_positive"]),
            )
        )
        matched_incidents = len(matching.scalars().all())
    logger.info(
        "Threat feed ingested",
        feed=feed.feed_name,
        ingested=ingested,
        skipped=skipped,
        matched=matched_incidents,
    )
    return ThreatIntelResponse(
        ingested=ingested,
        skipped=skipped,
        new_indicators=new_indicators,
        matched_incidents=matched_incidents,
    )


@router.get("/indicators", response_model=List[EventResponse])
async def list_indicators(
    indicator_type: Optional[str] = Query(None),
    source: Optional[str] = Query(None),
    severity: Optional[EventSeverity] = Query(None),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    query = select(Event).where(Event.event_type == "threat_intel")
    if indicator_type:
        query = query.where(Event.raw_data["indicator_type"].as_string() == indicator_type)
    if source:
        query = query.where(Event.source == source)
    if severity:
        query = query.where(Event.severity == severity)
    if search:
        query = query.where(Event.title.ilike(f"%{search}%") | Event.description.ilike(f"%{search}%"))
    query = query.order_by(desc(Event.created_at))
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/mitre/techniques")
async def list_mitre_techniques(search: Optional[str] = Query(None), tactic: Optional[str] = Query(None)):
    await mitre_manager.load_data()
    if tactic:
        techniques = mitre_manager.get_techniques_by_tactic(tactic)
    elif search:
        techniques = mitre_manager.search_techniques(search)
    else:
        techniques = list(mitre_manager.get_all_techniques().values())
    return techniques[:100]


@router.get("/mitre/tactics")
async def list_mitre_tactics():
    await mitre_manager.load_data()
    return list(mitre_manager.get_all_tactics().values())


@router.post("/analyze-incident/{incident_id}")
async def analyze_incident_threats(incident_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Incident not found")
    await mitre_manager.load_data()
    incident_data = {
        "title": incident.title,
        "description": incident.description,
        "indicators": incident.indicators or [],
    }
    mapped_techniques = mitre_manager.map_incident_to_techniques(incident_data)
    lifecycle_coverage = mitre_manager.get_attack_lifecycle_coverage(mapped_techniques)
    remediation = mitre_manager.generate_remediation_plan(mapped_techniques)
    if mapped_techniques:
        incident.mitre_techniques = list(set(list(incident.mitre_techniques or []) + mapped_techniques))
        await db.commit()
    return {
        "incident_id": incident_id,
        "mapped_techniques": [mitre_manager.get_technique(t) for t in mapped_techniques if mitre_manager.get_technique(t)],
        "technique_ids": mapped_techniques,
        "lifecycle_coverage": lifecycle_coverage,
        "remediation_plan": remediation,
        "coverage_score": sum(1 for v in lifecycle_coverage.values() if v) / max(len(lifecycle_coverage), 1),
    }


@router.get("/stats", response_model=EventStats)
async def threat_intel_stats(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    total = await db.execute(
        select(func.count(Event.id)).where(Event.event_type == "threat_intel")
    )
    by_severity = await db.execute(
        select(Event.severity, func.count(Event.id))
        .where(Event.event_type == "threat_intel")
        .group_by(Event.severity)
    )
    by_source = await db.execute(
        select(Event.source, func.count(Event.id))
        .where(Event.event_type == "threat_intel")
        .group_by(Event.source)
    )
    return EventStats(
        total_events=total.scalar() or 0,
        by_severity={str(row[0].value if hasattr(row[0], 'value') else row[0]): row[1] for row in by_severity.all()},
        by_category={"threat": total.scalar() or 0},
        by_source={str(row[0]): row[1] for row in by_source.all()},
        time_range_hours=24,
    )
