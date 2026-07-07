from typing import Dict, Any, List, Optional, Set, Callable
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field, asdict
import json
import uuid
from app.core.logger import logger
from app.core.event_bus import event_bus


class EntityStatus(str, Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    COMPROMISED = "compromised"
    OFFLINE = "offline"
    UNDER_ATTACK = "under_attack"
    ISOLATED = "isolated"
    RECOVERING = "recovering"
    UNKNOWN = "unknown"


class EntityCategory(str, Enum):
    SERVER = "server"
    NETWORK_DEVICE = "network_device"
    IOT_DEVICE = "iot_device"
    OT_DEVICE = "ot_device"
    APPLICATION = "application"
    DATABASE = "database"
    IDENTITY = "identity"
    USER = "user"
    CLOUD_SERVICE = "cloud_service"
    CREDENTIAL = "credential"


@dataclass
class EntityState:
    entity_id: str
    category: EntityCategory
    status: EntityStatus = EntityStatus.HEALTHY
    properties: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)
    parent_id: Optional[str] = None
    connected_entities: Set[str] = field(default_factory=set)
    last_updated: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    history: List[Dict[str, Any]] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "category": self.category.value,
            "status": self.status.value,
            "properties": self.properties,
            "tags": self.tags,
            "parent_id": self.parent_id,
            "connected_entities": list(self.connected_entities),
            "last_updated": self.last_updated,
            "metadata": self.metadata,
        }

    def snapshot(self) -> Dict[str, Any]:
        return {
            "entity_id": self.entity_id,
            "category": self.category.value,
            "status": self.status.value,
            "properties": dict(self.properties),
            "tags": list(self.tags),
            "last_updated": self.last_updated,
        }


@dataclass
class StateChange:
    change_id: str
    entity_id: str
    previous_status: Optional[EntityStatus]
    new_status: EntityStatus
    previous_properties: Optional[Dict[str, Any]]
    new_properties: Optional[Dict[str, Any]]
    timestamp: str
    source: str
    description: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "change_id": self.change_id,
            "entity_id": self.entity_id,
            "previous_status": self.previous_status.value if self.previous_status else None,
            "new_status": self.new_status.value,
            "timestamp": self.timestamp,
            "source": self.source,
            "description": self.description,
        }


STATE_CHANGE_TOPIC = "digital_twin.state_change"
STATE_SYNC_TOPIC = "digital_twin.sync"


class StateManager:
    def __init__(self):
        self._entities: Dict[str, EntityState] = {}
        self._change_history: List[StateChange] = []
        self._change_callbacks: List[Callable] = []
        self._max_history = 10000

    async def register_entity(
        self,
        entity_id: str,
        category: EntityCategory,
        properties: Dict[str, Any] = None,
        tags: List[str] = None,
        parent_id: str = None,
    ) -> EntityState:
        entity = EntityState(
            entity_id=entity_id,
            category=category,
            properties=properties or {},
            tags=tags or [],
            parent_id=parent_id,
        )
        self._entities[entity_id] = entity
        logger.info("Entity registered in state manager", entity_id=entity_id, category=category.value)
        return entity

    async def update_status(
        self,
        entity_id: str,
        new_status: EntityStatus,
        source: str = "system",
        description: str = "",
        propagate: bool = True,
    ) -> Optional[StateChange]:
        entity = self._entities.get(entity_id)
        if not entity:
            logger.warning("Entity not found for status update", entity_id=entity_id)
            return None

        previous_status = entity.status
        if previous_status == new_status:
            return None

        change = StateChange(
            change_id=str(uuid.uuid4()),
            entity_id=entity_id,
            previous_status=previous_status,
            new_status=new_status,
            previous_properties=dict(entity.properties),
            new_properties=None,
            timestamp=datetime.now(timezone.utc).isoformat(),
            source=source,
            description=description or f"Status changed from {previous_status.value} to {new_status.value}",
        )

        entity.status = new_status
        entity.last_updated = change.timestamp
        entity.history.append(change.to_dict())
        if len(entity.history) > self._max_history:
            entity.history = entity.history[-self._max_history:]

        self._change_history.append(change)
        if len(self._change_history) > self._max_history:
            self._change_history = self._change_history[-self._max_history:]

        await self._notify_change(change)
        await event_bus.publish(STATE_CHANGE_TOPIC, change.to_dict())

        if propagate:
            await self._propagate_change(entity_id, change, source)

        return change

    async def update_properties(
        self,
        entity_id: str,
        properties: Dict[str, Any],
        source: str = "system",
        description: str = "",
    ) -> Optional[StateChange]:
        entity = self._entities.get(entity_id)
        if not entity:
            logger.warning("Entity not found for property update", entity_id=entity_id)
            return None

        previous_properties = dict(entity.properties)
        entity.properties.update(properties)
        entity.last_updated = datetime.now(timezone.utc).isoformat()

        change = StateChange(
            change_id=str(uuid.uuid4()),
            entity_id=entity_id,
            previous_status=entity.status,
            new_status=entity.status,
            previous_properties=previous_properties,
            new_properties=dict(entity.properties),
            timestamp=entity.last_updated,
            source=source,
            description=description or "Properties updated",
        )

        entity.history.append(change.to_dict())
        self._change_history.append(change)

        await self._notify_change(change)
        await event_bus.publish(STATE_CHANGE_TOPIC, change.to_dict())

        return change

    async def add_connection(self, entity_id: str, connected_id: str):
        entity = self._entities.get(entity_id)
        connected = self._entities.get(connected_id)
        if entity and connected:
            entity.connected_entities.add(connected_id)
            connected.connected_entities.add(entity_id)

    async def remove_connection(self, entity_id: str, connected_id: str):
        entity = self._entities.get(entity_id)
        connected = self._entities.get(connected_id)
        if entity:
            entity.connected_entities.discard(connected_id)
        if connected:
            connected.connected_entities.discard(entity_id)

    def get_entity(self, entity_id: str) -> Optional[EntityState]:
        return self._entities.get(entity_id)

    def get_entities_by_category(self, category: EntityCategory) -> List[EntityState]:
        return [e for e in self._entities.values() if e.category == category]

    def get_entities_by_status(self, status: EntityStatus) -> List[EntityState]:
        return [e for e in self._entities.values() if e.status == status]

    def get_entities_by_tag(self, tag: str) -> List[EntityState]:
        return [e for e in self._entities.values() if tag in e.tags]

    def get_all_entities(self) -> List[EntityState]:
        return list(self._entities.values())

    def get_entity_count(self) -> Dict[str, int]:
        counts = {}
        for entity in self._entities.values():
            cat = entity.category.value
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    async def get_timeline(
        self,
        entity_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        if entity_id:
            entity = self._entities.get(entity_id)
            if not entity:
                return []
            return entity.history[-limit:]

        return [c.to_dict() for c in self._change_history[-limit:]]

    def get_status_summary(self) -> Dict[str, int]:
        summary = {}
        for entity in self._entities.values():
            status = entity.status.value
            summary[status] = summary.get(status, 0) + 1
        return summary

    async def unregister_entity(self, entity_id: str):
        entity = self._entities.pop(entity_id, None)
        if entity:
            for connected_id in list(entity.connected_entities):
                await self.remove_connection(entity_id, connected_id)
            logger.info("Entity unregistered", entity_id=entity_id)

    async def _propagate_change(self, entity_id: str, change: StateChange, source: str):
        entity = self._entities.get(entity_id)
        if not entity:
            return

        if change.new_status in (EntityStatus.COMPROMISED, EntityStatus.UNDER_ATTACK):
            propagation_status = EntityStatus.DEGRADED
            if change.new_status == EntityStatus.UNDER_ATTACK:
                propagation_status = EntityStatus.DEGRADED
            elif change.new_status == EntityStatus.COMPROMISED:
                propagation_status = EntityStatus.COMPROMISED

            for connected_id in entity.connected_entities:
                connected = self._entities.get(connected_id)
                if connected and connected.status == EntityStatus.HEALTHY:
                    await self.update_status(
                        connected_id,
                        propagation_status,
                        source=f"propagation_from_{entity_id}",
                        description=f"Status propagated due to {entity_id} status change",
                        propagate=False,
                    )

    def on_change(self, callback: Callable):
        self._change_callbacks.append(callback)

    async def _notify_change(self, change: StateChange):
        for callback in self._change_callbacks:
            try:
                await callback(change)
            except Exception as e:
                logger.error("State change callback failed", error=str(e))

    def get_forked_state(self) -> Dict[str, EntityState]:
        return {
            eid: EntityState(
                entity_id=e.entity_id,
                category=e.category,
                status=e.status,
                properties=dict(e.properties),
                tags=list(e.tags),
                parent_id=e.parent_id,
                connected_entities=set(e.connected_entities),
                last_updated=e.last_updated,
                metadata=dict(e.metadata),
            )
            for eid, e in self._entities.items()
        }

    def restore_forked_state(self, forked: Dict[str, EntityState]):
        self._entities = forked

    async def clear(self):
        self._entities.clear()
        self._change_history.clear()
        logger.info("State manager cleared")


state_manager = StateManager()
