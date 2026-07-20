from app.world_model.audit import audit, AuditTrail
from app.world_model.entity_state import EntityState, Evidence, Observation
from app.world_model.model import CyberWorldModel, Relation, world_model
from app.world_model.seed import build_seed


def bootstrap() -> None:
    if not world_model.entities:
        world_model.load_seed(build_seed())


bootstrap()

__all__ = [
    "audit",
    "AuditTrail",
    "bootstrap",
    "build_seed",
    "CyberWorldModel",
    "EntityState",
    "Evidence",
    "Observation",
    "Relation",
    "world_model",
]
