from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from datetime import datetime
from app.core.logger import logger
from app.core.event_bus import event_bus


class BaseAgent(ABC):
    def __init__(self, name: str, agent_type: str, version: str = "1.0.0"):
        self.name = name
        self.agent_type = agent_type
        self.version = version
        self.memory: Dict[str, Any] = {}
        self.confidence_threshold: float = 0.7
        self.last_run: Optional[datetime] = None
        self.metrics: Dict[str, Any] = {"runs": 0, "successes": 0, "failures": 0}

    @abstractmethod
    async def process(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        pass

    async def validate_input(self, data: Dict[str, Any]) -> bool:
        return bool(data)

    async def publish_event(self, topic: str, data: Dict[str, Any]):
        data["agent"] = self.name
        data["agent_type"] = self.agent_type
        data["timestamp"] = datetime.utcnow().isoformat()
        await event_bus.publish(topic, data)

    def update_metrics(self, success: bool):
        self.metrics["runs"] += 1
        if success:
            self.metrics["successes"] += 1
        else:
            self.metrics["failures"] += 1

    def get_status(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.agent_type,
            "version": self.version,
            "last_run": self.last_run,
            "metrics": self.metrics
        }
