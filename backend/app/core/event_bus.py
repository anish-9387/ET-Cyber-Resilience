import json
from typing import Callable, Dict, Any, Optional
from app.core.config import settings


class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, list] = {}
        self._producer = None
        self._consumer = None

    async def publish(self, topic: str, message: Dict[str, Any]):
        from app.core.database import redis_client
        msg_str = json.dumps(message, default=str)
        await redis_client.publish(topic, msg_str)

    async def subscribe(self, topic: str, callback: Callable):
        if topic not in self._subscribers:
            self._subscribers[topic] = []
        self._subscribers[topic].append(callback)

    async def start_consumer(self, topic: str):
        from app.core.database import redis_client
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(topic)
        async for message in pubsub.listen():
            if message["type"] == "message":
                data = json.loads(message["data"])
                for callback in self._subscribers.get(topic, []):
                    await callback(data)


event_bus = EventBus()
