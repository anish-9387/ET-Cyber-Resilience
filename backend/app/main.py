from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import router as api_router
from app.core.config import settings
from app.core.database import close_db, init_db
from app.core.logger import logger
from app.world_model import bootstrap as bootstrap_world_model
from app.world_model import world_model


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("overlook_starting", version=settings.APP_VERSION)

    try:
        await init_db()
        logger.info("database_initialized", url=settings.DATABASE_URL.split("://")[0])
    except Exception as exc:
        logger.error("database_init_failed", error=str(exc))

    if settings.WORLD_MODEL_SEED_ON_STARTUP:
        try:
            bootstrap_world_model()
            snapshot = world_model.snapshot()
            logger.info(
                "world_model_seeded",
                entities=snapshot.get("entity_count"),
                relations=snapshot.get("relation_count"),
            )
        except Exception as exc:
            logger.error("world_model_seed_failed", error=str(exc))

    yield

    await close_db()
    logger.info("overlook_shutdown_complete")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "Cyber World Model for Critical National Infrastructure. "
        "Maintains a probabilistic model of the environment, forecasts attacker "
        "futures, evaluates defensive strategies against mission impact, and "
        "records every automated decision in an audit trail."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api/v1")


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "version": settings.APP_VERSION,
        "name": settings.APP_NAME,
    }
