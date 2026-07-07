from fastapi import APIRouter
from app.api import agents, auth, digital_twin, incidents, threat_intel, analytics, health

router = APIRouter()
router.include_router(agents.router, prefix="/agents", tags=["Agents"])
router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
router.include_router(digital_twin.router, prefix="/digital-twin", tags=["Digital Twin"])
router.include_router(incidents.router, prefix="/incidents", tags=["Incidents"])
router.include_router(threat_intel.router, prefix="/threat-intel", tags=["Threat Intelligence"])
router.include_router(analytics.router, prefix="/analytics", tags=["Analytics"])
router.include_router(health.router, prefix="/health", tags=["Health"])
