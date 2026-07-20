"""Event bus.

Redis pub/sub is used when available so that multiple workers share a bus. When
Redis is disabled the bus degrades to in-process dispatch, which keeps the agent
pipeline fully functional for a single-process demo. Previously every publish
went to Redis and nothing ever subscribed, so no agent reacted to anything.
"""

import asyncio
import json
from typing import Any, Awaitable, Callable, Dict, List

from app.core.logger import logger


class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[Dict[str, Any]], Awaitable[None]]]] = {}
        self._history: List[Dict[str, Any]] = []
        self._history_limit = 1000

    async def publish(self, topic: str, message: Dict[str, Any]) -> None:
        record = {"topic": topic, **message}
        self._history.append(record)
        if len(self._history) > self._history_limit:
            del self._history[: len(self._history) - self._history_limit]

        await self._dispatch_local(topic, message)

        from app.core.database import redis_client

        if redis_client is None:
            return
        try:
            await redis_client.publish(topic, json.dumps(message, default=str))
        except Exception as exc:
            logger.warning("event_bus_publish_failed", topic=topic, error=str(exc))

    async def _dispatch_local(self, topic: str, message: Dict[str, Any]) -> None:
        callbacks = self._subscribers.get(topic, [])
        if not callbacks:
            return
        results = await asyncio.gather(
            *(cb(message) for cb in callbacks), return_exceptions=True
        )
        for result in results:
            if isinstance(result, Exception):
                logger.warning("event_handler_failed", topic=topic, error=str(result))

    async def subscribe(self, topic: str, callback: Callable) -> None:
        self._subscribers.setdefault(topic, []).append(callback)

    def recent(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._history[-limit:]

    async def start_consumer(self, topic: str) -> None:
        from app.core.database import redis_client

        if redis_client is None:
            logger.info("event_bus_consumer_skipped", topic=topic, reason="redis_disabled")
            return
        pubsub = redis_client.pubsub()
        await pubsub.subscribe(topic)
        async for message in pubsub.listen():
            if message["type"] == "message":
                await self._dispatch_local(topic, json.loads(message["data"]))


event_bus = EventBus()
