from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db, redis_client, neo4j_driver, qdrant_client
from app.core.config import settings
from app.core.logger import logger

router = APIRouter()


@router.get("")
async def health_check():
    services = {
        "api": {"status": "healthy"},
        "database": {"status": "unknown"},
        "redis": {"status": "unknown"},
        "neo4j": {"status": "unknown"},
        "qdrant": {"status": "unknown"},
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
        logger.error("Database health check failed", error=str(e))
    try:
        await redis_client.ping()
        services["redis"]["status"] = "healthy"
    except Exception as e:
        services["redis"]["status"] = "unhealthy"
        services["redis"]["error"] = str(e)
        logger.error("Redis health check failed", error=str(e))
    try:
        async with neo4j_driver.session() as session:
            await session.run("RETURN 1")
        services["neo4j"]["status"] = "healthy"
    except Exception as e:
        services["neo4j"]["status"] = "unhealthy"
        services["neo4j"]["error"] = str(e)
        logger.error("Neo4j health check failed", error=str(e))
    try:
        qdrant_client.get_collections()
        services["qdrant"]["status"] = "healthy"
    except Exception as e:
        services["qdrant"]["status"] = "unhealthy"
        services["qdrant"]["error"] = str(e)
        logger.error("Qdrant health check failed", error=str(e))
    all_healthy = all(s["status"] == "healthy" for s in services.values())
    return {
        "status": "healthy" if all_healthy else "degraded",
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
