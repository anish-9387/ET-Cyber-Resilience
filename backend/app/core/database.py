"""Datastore wiring.

Only the relational database is required. Neo4j, Qdrant and Redis are optional
enrichment layers: if they are disabled or unreachable the corresponding client
is left as ``None`` and callers fall back to the in-memory world model. This is
what lets ``uvicorn app.main:app`` come up on a laptop with nothing else running.
"""

from typing import Any, AsyncGenerator, Optional

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings
from app.core.logger import logger


class Base(DeclarativeBase):
    pass


def _engine_kwargs() -> dict:
    if settings.DATABASE_URL.startswith("sqlite"):
        return {"echo": settings.DEBUG}
    return {"echo": settings.DEBUG, "pool_pre_ping": True}


engine = create_async_engine(settings.DATABASE_URL, **_engine_kwargs())
async_session = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


neo4j_driver: Optional[Any] = None
qdrant_client: Optional[Any] = None
redis_client: Optional[Any] = None


def _init_neo4j() -> Optional[Any]:
    if not settings.NEO4J_ENABLED:
        return None
    try:
        from neo4j import AsyncGraphDatabase

        return AsyncGraphDatabase.driver(
            settings.NEO4J_URI,
            auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
        )
    except Exception as exc:
        logger.warning("neo4j_unavailable", error=str(exc))
        return None


def _init_qdrant() -> Optional[Any]:
    if not settings.QDRANT_ENABLED:
        return None
    try:
        from qdrant_client import QdrantClient

        return QdrantClient(
            host=settings.QDRANT_HOST, port=settings.QDRANT_PORT, timeout=2.0
        )
    except Exception as exc:
        logger.warning("qdrant_unavailable", error=str(exc))
        return None


def _init_redis() -> Optional[Any]:
    if not settings.REDIS_ENABLED:
        return None
    try:
        import redis.asyncio as redis

        return redis.from_url(settings.REDIS_URL, decode_responses=True)
    except Exception as exc:
        logger.warning("redis_unavailable", error=str(exc))
        return None


neo4j_driver = _init_neo4j()
qdrant_client = _init_qdrant()
redis_client = _init_redis()


def neo4j_available() -> bool:
    return neo4j_driver is not None


def qdrant_available() -> bool:
    return qdrant_client is not None


def redis_available() -> bool:
    return redis_client is not None


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with async_session() as session:
        yield session


async def init_db() -> None:
    from app import models  # noqa: F401  - ensures tables are registered

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_db() -> None:
    await engine.dispose()
    if neo4j_driver is not None:
        try:
            await neo4j_driver.close()
        except Exception as exc:
            logger.warning("neo4j_close_failed", error=str(exc))
    if redis_client is not None:
        try:
            await redis_client.aclose()
        except Exception as exc:
            logger.warning("redis_close_failed", error=str(exc))
