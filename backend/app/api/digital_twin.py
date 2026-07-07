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
    import uuid
    sim_id = str(uuid.uuid4())
    logger.info("Simulation started", sim_id=sim_id, scenario=request.scenario, asset_id=request.asset_id)
    start = datetime.now(timezone.utc)
    impact_analysis = {
        "scenario": request.scenario,
        "parameters": request.parameters,
        "estimated_cpu_impact": request.parameters.get("load", 50),
        "estimated_memory_impact": request.parameters.get("memory", 30),
        "affected_services": request.parameters.get("services", []),
        "blast_radius": request.parameters.get("blast_radius", "local"),
    }
    risk_score = min(100, sum([
        30 if request.parameters.get("critical", False) else 10,
        len(request.parameters.get("services", [])) * 5,
        20 if request.parameters.get("blast_radius", "local") == "network" else 10,
    ]))
    recommendations = [
        f"Review access controls for assets similar to {request.asset_id}",
        "Ensure backup systems are operational",
        "Verify monitoring coverage for this scenario",
        "Update incident response playbook if gaps identified",
    ]
    result = SimulationResult(
        simulation_id=sim_id,
        asset_id=request.asset_id,
        scenario=request.scenario,
        status="completed",
        impact_analysis=impact_analysis,
        risk_score=risk_score,
        recommendations=recommendations,
        started_at=start,
        completed_at=datetime.now(timezone.utc),
    )
    logger.info("Simulation completed", sim_id=sim_id, risk_score=risk_score)
    return result
