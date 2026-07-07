from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timezone
from enum import Enum
from dataclasses import dataclass, field
import uuid
from app.core.logger import logger
from app.core.event_bus import event_bus
from app.knowledge_graph.graph_manager import graph_manager
from app.digital_twin.state_manager import (
    state_manager,
    StateManager,
    EntityState,
    EntityCategory,
    EntityStatus,
    StateChange,
)
from app.digital_twin.simulation_engine import simulation_engine, SimulationScenario, SimulationReport


class TwinStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    SYNCHRONIZING = "synchronizing"
    FORKED = "forked"
    STOPPED = "stopped"


@dataclass
class TwinInstance:
    twin_id: str
    name: str
    status: TwinStatus
    created_at: str
    synced_at: Optional[str] = None
    forked_from: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


SYNC_TOPIC = "digital_twin.sync_request"


class TwinManager:
    def __init__(self):
        self._twins: Dict[str, TwinInstance] = {}
        self._active_twin_id: Optional[str] = None
        self._forked_states: Dict[str, Dict[str, EntityState]] = {}
        self._sync_interval_seconds = 60

    async def create_twin(
        self,
        name: str,
        metadata: Dict[str, Any] = None,
    ) -> TwinInstance:
        twin_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        twin = TwinInstance(
            twin_id=twin_id,
            name=name,
            status=TwinStatus.ACTIVE,
            created_at=now,
            metadata=metadata or {},
        )
        self._twins[twin_id] = twin
        self._active_twin_id = twin_id

        await self._initialize_from_graph(twin_id)

        logger.info("Digital twin created", twin_id=twin_id, name=name)
        return twin

    async def _initialize_from_graph(self, twin_id: str):
        query = """
        MATCH (n)
        RETURN elementId(n) AS node_id,
               labels(n) AS labels,
               properties(n) AS props
        LIMIT 500
        """
        try:
            nodes = await graph_manager.query(query)
            for node in nodes:
                node_id = node["node_id"]
                labels = node["labels"]
                props = node["props"]

                category = self._map_label_to_category(labels)
                status = self._infer_status(props)

                await state_manager.register_entity(
                    entity_id=node_id,
                    category=category,
                    properties=props,
                    tags=labels,
                )
                await state_manager.update_status(
                    node_id, status, source="graph_init", propagate=False
                )

            await self._initialize_connections()

            twin = self._twins.get(twin_id)
            if twin:
                twin.synced_at = datetime.now(timezone.utc).isoformat()
                twin.status = TwinStatus.SYNCHRONIZING

            logger.info(
                "Twin initialized from graph",
                twin_id=twin_id,
                entity_count=len(nodes),
            )
        except Exception as e:
            logger.error("Failed to initialize twin from graph", error=str(e))

    async def _initialize_connections(self):
        query = """
        MATCH (a)-[r]->(b)
        RETURN elementId(a) AS source_id,
               elementId(b) AS target_id,
               type(r) AS rel_type
        LIMIT 2000
        """
        try:
            rels = await graph_manager.query(query)
            for rel in rels:
                await state_manager.add_connection(
                    rel["source_id"], rel["target_id"]
                )
        except Exception as e:
            logger.error("Failed to initialize connections", error=str(e))

    async def sync_from_graph(self, twin_id: Optional[str] = None):
        twin_id = twin_id or self._active_twin_id
        if not twin_id or twin_id not in self._twins:
            logger.warning("No active twin to sync")
            return

        twin = self._twins[twin_id]
        twin.status = TwinStatus.SYNCHRONIZING

        query = """
        MATCH (n)
        RETURN elementId(n) AS node_id,
               labels(n) AS labels,
               properties(n) AS props
        """
        try:
            nodes = await graph_manager.query(query)
            current_ids = {e.entity_id for e in state_manager.get_all_entities()}
            graph_ids = set()

            for node in nodes:
                node_id = node["node_id"]
                graph_ids.add(node_id)

                existing = state_manager.get_entity(node_id)
                if existing:
                    await state_manager.update_properties(
                        node_id, node["props"], source="graph_sync"
                    )
                else:
                    category = self._map_label_to_category(node["labels"])
                    await state_manager.register_entity(
                        entity_id=node_id,
                        category=category,
                        properties=node["props"],
                        tags=node["labels"],
                    )

            for stale_id in current_ids - graph_ids:
                await state_manager.unregister_entity(stale_id)

            twin.synced_at = datetime.now(timezone.utc).isoformat()
            twin.status = TwinStatus.ACTIVE
            logger.info("Twin synced from graph", twin_id=twin_id)
        except Exception as e:
            logger.error("Twin sync failed", error=str(e))
            twin.status = TwinStatus.ACTIVE

    async def fork_twin(self, name: str = None) -> Tuple[str, TwinInstance]:
        if not self._active_twin_id:
            raise RuntimeError("No active twin to fork")

        current_state = state_manager.get_forked_state()
        fork_id = str(uuid.uuid4())
        self._forked_states[fork_id] = current_state

        now = datetime.now(timezone.utc).isoformat()
        forked_twin = TwinInstance(
            twin_id=fork_id,
            name=name or f"Fork of {self._twins[self._active_twin_id].name}",
            status=TwinStatus.FORKED,
            created_at=now,
            forked_from=self._active_twin_id,
        )
        self._twins[fork_id] = forked_twin

        state_manager.restore_forked_state(current_state)

        logger.info("Twin forked", fork_id=fork_id, source=self._active_twin_id)
        return fork_id, forked_twin

    async def restore_fork(self, fork_id: str):
        if fork_id not in self._forked_states:
            raise ValueError(f"Fork {fork_id} not found")

        forked_state = self._forked_states[fork_id]
        state_manager.restore_forked_state(forked_state)

        twin = self._twins.get(fork_id)
        if twin:
            twin.status = TwinStatus.ACTIVE
            self._active_twin_id = fork_id

        logger.info("Fork restored", fork_id=fork_id)

    async def discard_fork(self, fork_id: str):
        self._forked_states.pop(fork_id, None)
        twin = self._twins.pop(fork_id, None)
        if twin:
            logger.info("Fork discarded", fork_id=fork_id)

    async def run_simulation(
        self,
        scenario: SimulationScenario,
        twin_id: Optional[str] = None,
    ) -> SimulationReport:
        twin_id = twin_id or self._active_twin_id
        if not twin_id or twin_id not in self._twins:
            raise RuntimeError("No active twin for simulation")

        fork_id, _ = await self.fork_twin(name=f"sim_{scenario.scenario_id}")
        try:
            report = await simulation_engine.run_scenario(scenario)
            return report
        finally:
            await self.discard_fork(fork_id)

    async def run_simulation_on_fork(
        self,
        scenario: SimulationScenario,
        fork_id: str,
    ) -> SimulationReport:
        await self.restore_fork(fork_id)
        return await simulation_engine.run_scenario(scenario)

    async def get_state_summary(self) -> Dict[str, Any]:
        entity_count = state_manager.get_entity_count()
        status_summary = state_manager.get_status_summary()
        return {
            "active_twin_id": self._active_twin_id,
            "twin_count": len(self._twins),
            "entity_counts": entity_count,
            "status_summary": status_summary,
            "fork_count": len(self._forked_states),
        }

    async def simulate_event(
        self,
        entity_id: str,
        event_type: str,
        event_data: Dict[str, Any],
    ):
        logger.info(
            "Simulating event on twin",
            entity_id=entity_id,
            event_type=event_type,
        )

        if event_type == "compromise":
            await state_manager.update_status(
                entity_id,
                EntityStatus.COMPROMISED,
                source="event_simulation",
                description=event_data.get("description", "Simulated compromise"),
            )
        elif event_type == "degrade":
            await state_manager.update_status(
                entity_id,
                EntityStatus.DEGRADED,
                source="event_simulation",
                description=event_data.get("description", "Simulated degradation"),
            )
        elif event_type == "recover":
            await state_manager.update_status(
                entity_id,
                EntityStatus.RECOVERING,
                source="event_simulation",
                description=event_data.get("description", "Simulated recovery"),
            )
        elif event_type == "isolate":
            await state_manager.update_status(
                entity_id,
                EntityStatus.ISOLATED,
                source="event_simulation",
                description=event_data.get("description", "Simulated isolation"),
            )
        elif event_type == "offline":
            await state_manager.update_status(
                entity_id,
                EntityStatus.OFFLINE,
                source="event_simulation",
                description=event_data.get("description", "Simulated outage"),
            )

        await event_bus.publish(
            "digital_twin.simulated_event",
            {
                "entity_id": entity_id,
                "event_type": event_type,
                "event_data": event_data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    async def get_twin(self, twin_id: str = None) -> Optional[TwinInstance]:
        twin_id = twin_id or self._active_twin_id
        return self._twins.get(twin_id)

    async def list_twins(self) -> List[TwinInstance]:
        return list(self._twins.values())

    async def delete_twin(self, twin_id: str):
        twin = self._twins.pop(twin_id, None)
        if twin:
            if self._active_twin_id == twin_id:
                self._active_twin_id = None
            logger.info("Twin deleted", twin_id=twin_id)

    def _map_label_to_category(self, labels: List[str]) -> EntityCategory:
        label_to_category = {
            "Server": EntityCategory.SERVER,
            "Firewall": EntityCategory.NETWORK_DEVICE,
            "Switch": EntityCategory.NETWORK_DEVICE,
            "IoTDevice": EntityCategory.IOT_DEVICE,
            "OTDevice": EntityCategory.OT_DEVICE,
            "Application": EntityCategory.APPLICATION,
            "Database": EntityCategory.DATABASE,
            "Identity": EntityCategory.IDENTITY,
            "User": EntityCategory.USER,
            "CloudService": EntityCategory.CLOUD_SERVICE,
            "Credential": EntityCategory.CREDENTIAL,
        }
        for label in labels:
            if label in label_to_category:
                return label_to_category[label]
        return EntityCategory.SERVER

    def _infer_status(self, properties: Dict[str, Any]) -> EntityStatus:
        if properties.get("is_compromised"):
            return EntityStatus.COMPROMISED
        if properties.get("failed_login_attempts", 0) > 5:
            return EntityStatus.DEGRADED
        if properties.get("is_active") is False:
            return EntityStatus.OFFLINE
        return EntityStatus.HEALTHY


twin_manager = TwinManager()
