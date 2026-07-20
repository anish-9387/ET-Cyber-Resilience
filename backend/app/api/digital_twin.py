from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_
from typing import Optional, List
from app.core.database import get_db, neo4j_driver
from app.models import Asset, AssetRelationship
from app.schemas.digital_twin import (
    AssetCreate, AssetUpdate, AssetResponse, AssetSearchParams,
    RelationshipCreate, RelationshipResponse, RelationshipType,
    DigitalTwinState, DigitalTwinSimulation, SimulationResult,
    AssetGraph, AssetCriticality, AssetType,
)
from app.core.logger import logger
from datetime import datetime, timezone

router = APIRouter()


@router.get("/assets", response_model=List[AssetResponse])
async def list_assets(
    asset_type: Optional[AssetType] = Query(None),
    criticality: Optional[AssetCriticality] = Query(None),
    search: Optional[str] = Query(None),
    department: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    query = select(Asset)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if criticality:
        query = query.where(Asset.criticality == criticality)
    if department:
        query = query.where(Asset.department == department)
    if search:
        query = query.where(
            or_(
                Asset.name.ilike(f"%{search}%"),
                Asset.hostname.ilike(f"%{search}%"),
                Asset.ip_address.ilike(f"%{search}%"),
            )
        )
    query = query.offset((page - 1) * page_size).limit(page_size)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/assets/{asset_id}", response_model=AssetResponse)
async def get_asset(asset_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    return asset


@router.post("/assets", response_model=AssetResponse, status_code=status.HTTP_201_CREATED)
async def create_asset(request: AssetCreate, db: AsyncSession = Depends(get_db)):
    asset = Asset(
        name=request.name,
        asset_type=request.asset_type,
        ip_address=request.ip_address,
        hostname=request.hostname,
        domain=request.domain,
        os=request.os,
        os_version=request.os_version,
        criticality=request.criticality,
        location=request.location,
        department=request.department,
        owner=request.owner,
        tags=request.tags or [],
        metadata_=request.metadata or {},
    )
    db.add(asset)
    await db.commit()
    await db.refresh(asset)
    try:
        async with neo4j_driver.session() as neo4j_session:
            await neo4j_session.run(
                "CREATE (a:Asset {id: $id, name: $name, type: $type, criticality: $criticality})",
                id=asset.id, name=asset.name, type=asset.asset_type.value, criticality=asset.criticality.value,
            )
    except Exception as e:
        logger.warning("Failed to create Neo4j node for asset", asset_id=asset.id, error=str(e))
    logger.info("Asset created", asset_id=asset.id, name=asset.name)
    return asset


@router.put("/assets/{asset_id}", response_model=AssetResponse)
async def update_asset(asset_id: str, request: AssetUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    update_data = request.model_dump(exclude_unset=True)
    for field, value in update_data.items():
        if field == "metadata":
            field = "metadata_"
        setattr(asset, field, value)
    asset.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(asset)
    logger.info("Asset updated", asset_id=asset_id)
    return asset


@router.delete("/assets/{asset_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_asset(asset_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    await db.delete(asset)
    await db.commit()
    try:
        async with neo4j_driver.session() as neo4j_session:
            await neo4j_session.run("MATCH (a:Asset {id: $id}) DETACH DELETE a", id=asset_id)
    except Exception as e:
        logger.warning("Failed to delete Neo4j node", asset_id=asset_id, error=str(e))
    logger.info("Asset deleted", asset_id=asset_id)


@router.post("/relationships", response_model=RelationshipResponse, status_code=status.HTTP_201_CREATED)
async def create_relationship(request: RelationshipCreate, db: AsyncSession = Depends(get_db)):
    source = await db.execute(select(Asset).where(Asset.id == request.source_asset_id))
    if not source.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source asset not found")
    target = await db.execute(select(Asset).where(Asset.id == request.target_asset_id))
    if not target.scalar_one_or_none():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Target asset not found")
    rel = AssetRelationship(
        source_asset_id=request.source_asset_id,
        target_asset_id=request.target_asset_id,
        relationship_type=request.relationship_type,
        label=request.label,
        metadata_=request.metadata or {},
    )
    db.add(rel)
    await db.commit()
    await db.refresh(rel)
    try:
        async with neo4j_driver.session() as neo4j_session:
            await neo4j_session.run(
                "MATCH (a:Asset {id: $src}), (b:Asset {id: $tgt}) "
                "CREATE (a)-[r:RELATES_TO {type: $rel_type, label: $label}]->(b)",
                src=request.source_asset_id, tgt=request.target_asset_id,
                rel_type=request.relationship_type.value, label=request.label or "",
            )
    except Exception as e:
        logger.warning("Failed to create Neo4j relationship", error=str(e))
    logger.info("Relationship created", source=request.source_asset_id, target=request.target_asset_id)
    return rel


@router.get("/graph", response_model=AssetGraph)
async def get_asset_graph(
    asset_id: Optional[str] = Query(None),
    depth: int = Query(1, ge=1, le=5),
    db: AsyncSession = Depends(get_db),
):
    if asset_id:
        rels_query = select(AssetRelationship).where(
            (AssetRelationship.source_asset_id == asset_id) |
            (AssetRelationship.target_asset_id == asset_id)
        )
    else:
        rels_query = select(AssetRelationship).limit(200)
    rels_result = await db.execute(rels_query)
    rels = rels_result.scalars().all()
    asset_ids = set()
    for r in rels:
        asset_ids.add(r.source_asset_id)
        asset_ids.add(r.target_asset_id)
    if not asset_ids:
        return AssetGraph(nodes=[], relationships=[])
    assets_result = await db.execute(select(Asset).where(Asset.id.in_(asset_ids)))
    nodes = assets_result.scalars().all()
    return AssetGraph(
        nodes=[AssetResponse.model_validate(n) for n in nodes],
        relationships=[RelationshipResponse.model_validate(r) for r in rels],
    )


@router.get("/assets/{asset_id}/state", response_model=DigitalTwinState)
async def get_asset_state(asset_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Asset).where(Asset.id == asset_id))
    asset = result.scalar_one_or_none()
    if not asset:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Asset not found")
    try:
        async with neo4j_driver.session() as neo4j_session:
            neo4j_result = await neo4j_session.run(
                "MATCH (a:Asset {id: $id}) RETURN a.state as state", id=asset_id
            )
            record = await neo4j_result.single()
            state_data = record.get("state", {}) if record else {}
    except Exception:
        state_data = {}
    return DigitalTwinState(
        asset_id=asset_id,
        current_status=state_data.get("status", "unknown"),
        cpu_usage=state_data.get("cpu_usage"),
        memory_usage=state_data.get("memory_usage"),
        disk_usage=state_data.get("disk_usage"),
        network_in=state_data.get("network_in"),
        network_out=state_data.get("network_out"),
        running_processes=state_data.get("running_processes"),
        open_ports=state_data.get("open_ports"),
        vulnerabilities=state_data.get("vulnerabilities"),
        last_updated=datetime.now(timezone.utc),
    )


@router.post("/simulate", response_model=SimulationResult)
async def run_simulation(request: DigitalTwinSimulation):
    """Simulate compromise of an asset against the live world model.

    This used to echo the request parameters back and derive `risk_score` from a
    three-term constant sum, which meant the result was a function of the inputs
    rather than of the modelled environment. It now delegates to the world model:
    the asset is hypothetically compromised in a deep copy, the attack forecast
    and mission impact are recomputed, and the delta is reported. Nothing here
    touches production - the clone is discarded when the request completes.
    """
    from app.world_model import Observation, world_model
    from app.world_model.mission_impact import compute_mission_impact

    entity = world_model.resolve(request.asset_id) if hasattr(world_model, "resolve") \
        else world_model.get_entity(request.asset_id)
    if entity is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=(
                f"Asset '{request.asset_id}' is not present in the world model. "
                "Seed the topology or ingest telemetry for it first."
            ),
        )

    start = datetime.now(timezone.utc)
    sim_id = f"sim-{world_model.snapshot_id()}-{entity.id}"

    baseline_mission = compute_mission_impact(world_model)
    baseline_forecast = world_model.forecast(horizon_minutes=60)

    clone = world_model.clone()
    await clone.ingest_observation(
        Observation(
            entity_id=entity.id,
            source="digital_twin_simulation",
            description=(
                f"Hypothetical compromise of {entity.name} under scenario "
                f"'{request.scenario}'"
            ),
            technique_id=request.parameters.get("technique_id"),
            likelihood_ratio=50.0,
            severity="critical",
            timestamp=start,
            raw={"simulated": True, "scenario": request.scenario, **request.parameters},
        )
    )
    projected_mission = compute_mission_impact(clone)
    projected_forecast = clone.forecast(horizon_minutes=60)

    blast = list({n["id"]: n for n in clone.neighbors(entity.id)}.values())
    baseline_risk = float(baseline_mission.get("overall_mission_risk", 0.0))
    projected_risk = float(projected_mission.get("overall_mission_risk", 0.0))

    impact_analysis = {
        "scenario": request.scenario,
        "entity": {"id": entity.id, "name": entity.name, "criticality": entity.criticality},
        "baseline_mission_risk": round(baseline_risk, 6),
        "projected_mission_risk": round(projected_risk, 6),
        "mission_risk_delta": round(projected_risk - baseline_risk, 6),
        "degraded_functions": projected_mission.get("degraded_functions", []),
        "population_affected": projected_mission.get("population_affected"),
        "highest_safety_risk": projected_mission.get("highest_safety_risk"),
        "blast_radius_entities": [n["id"] for n in blast],
        "blast_radius_count": len(blast),
        "baseline_attack_success": baseline_forecast.get("attack_success"),
        "projected_attack_success": projected_forecast.get("attack_success"),
        "mode": "counterfactual_on_world_model_clone",
        "production_touched": False,
    }

    risk_score = round(min(100.0, projected_risk * 100.0), 2)

    recommendations = [
        f"Isolate {entity.name} - it neighbours {len(blast)} modelled entities"
    ]
    for fn in projected_mission.get("degraded_functions", [])[:3]:
        name = fn.get("name") if isinstance(fn, dict) else str(fn)
        recommendations.append(f"Prepare continuity plan for mission function '{name}'")
    if not projected_mission.get("degraded_functions"):
        recommendations.append(
            "No modelled mission function degrades from this asset alone - "
            "treat as containment priority rather than continuity risk"
        )

    logger.info(
        "simulation_completed",
        sim_id=sim_id,
        entity=entity.id,
        risk_score=risk_score,
        mission_delta=impact_analysis["mission_risk_delta"],
    )

    return SimulationResult(
        simulation_id=sim_id,
        asset_id=entity.id,
        scenario=request.scenario,
        status="completed",
        impact_analysis=impact_analysis,
        risk_score=risk_score,
        recommendations=recommendations,
        started_at=start,
        completed_at=datetime.now(timezone.utc),
    )
