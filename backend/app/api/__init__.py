from fastapi import APIRouter

from app.api import (
    agents,
    analytics,
    audit,
    auth,
    deception,
    decision,
    digital_twin,
    evaluation,
    forecast,
    health,
    incidents,
    ingest,
    mission,
    scenario,
    threat_intel,
    world_model,
)

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(health.router, prefix="/health", tags=["Health"])

router.include_router(world_model.router, prefix="/world-model", tags=["World Model"])
router.include_router(ingest.router, prefix="/ingest", tags=["Ingest"])
router.include_router(forecast.router, prefix="/forecast", tags=["Forecast"])
router.include_router(decision.router, prefix="/decision", tags=["Decision"])
router.include_router(mission.router, prefix="/mission", tags=["Mission Impact"])
router.include_router(deception.router, prefix="/deception", tags=["Deception"])
router.include_router(audit.router, prefix="/audit", tags=["Audit"])
router.include_router(scenario.router, prefix="/scenario", tags=["Scenario"])
router.include_router(evaluation.router, prefix="/evaluation", tags=["Evaluation"])

router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
router.include_router(digital_twin.router, prefix="/digital-twin", tags=["Digital Twin"])
router.include_router(threat_intel.router, prefix="/threat-intel", tags=["Threat Intelligence"])
router.include_router(analytics.router, prefix="/analytics", tags=["Analytics"])
router.include_router(agents.router, prefix="/agents", tags=["Agent Registry"])
