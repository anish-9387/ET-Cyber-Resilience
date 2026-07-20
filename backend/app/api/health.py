from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db, redis_client, neo4j_driver, qdrant_client
from app.core.config import settings
from app.core.logger import logger

router = APIRouter()


@router.get("")
async def health_check():
    services = {
        "api": {"status": "healthy", "required": True},
        "database": {"status": "unknown", "required": True},
        "redis": {"status": "disabled", "required": False},
        "neo4j": {"status": "disabled", "required": False},
        "qdrant": {"status": "disabled", "required": False},
        "world_model": {"status": "unknown", "required": True},
    }

    try:
        from sqlalchemy import text
        async for session in get_db():
            await session.execute(text("SELECT 1"))
            services["database"]["status"] = "healthy"
            break
    except Exception as e:
        services["database"]["status"] = "unhealthy"
        services["database"]["error"] = str(e)
        logger.error("database_health_check_failed", error=str(e))

    if redis_client is not None:
        try:
            await redis_client.ping()
            services["redis"]["status"] = "healthy"
        except Exception as e:
            services["redis"]["status"] = "unhealthy"
            services["redis"]["error"] = str(e)

    if neo4j_driver is not None:
        try:
            async with neo4j_driver.session() as session:
                await session.run("RETURN 1")
            services["neo4j"]["status"] = "healthy"
        except Exception as e:
            services["neo4j"]["status"] = "unhealthy"
            services["neo4j"]["error"] = str(e)

    if qdrant_client is not None:
        try:
            qdrant_client.get_collections()
            services["qdrant"]["status"] = "healthy"
        except Exception as e:
            services["qdrant"]["status"] = "unhealthy"
            services["qdrant"]["error"] = str(e)

    try:
        from app.world_model import world_model

        snapshot = world_model.snapshot()
        services["world_model"]["status"] = "healthy"
        services["world_model"]["entities"] = snapshot.get("entity_count", 0)
        services["world_model"]["observations"] = snapshot.get("observation_count", 0)
    except Exception as e:
        services["world_model"]["status"] = "unhealthy"
        services["world_model"]["error"] = str(e)

    required_healthy = all(
        s["status"] == "healthy" for s in services.values() if s.get("required")
    )
    return {
        "status": "healthy" if required_healthy else "degraded",
        "version": settings.APP_VERSION,
        "name": settings.APP_NAME,
        "services": services,
    }


@router.get("/live")
async def liveness():
    return {"status": "alive"}


@router.get("/ready")
async def readiness():
    try:
        async for session in get_db():
            from sqlalchemy import text
            await session.execute(text("SELECT 1"))
            break
        return {"status": "ready"}
    except Exception as e:
        return {"status": "not_ready", "error": str(e)}
