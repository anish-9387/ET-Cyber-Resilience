"""Core package.

Deliberately does NOT re-export eagerly. The previous version imported
`app.core.database` (which constructs a SQLAlchemy engine) and `app.core.llm`
(which constructs an Ollama client) at package import time, so a bare
`from app.core.logger import logger` pulled in the entire datastore and LLM
stack. That made every module transitively require infrastructure just to log,
and it broke standalone execution of the evaluation harness and the tests.

Import the submodule you actually need:

    from app.core.config import settings
    from app.core.logger import logger
    from app.core.database import get_db

`__getattr__` keeps the old flat access pattern working (PEP 562) but resolves
it lazily, so nothing is constructed until it is genuinely used.
"""

from typing import Any

_LAZY_EXPORTS = {
    "settings": "app.core.config",
    "engine": "app.core.database",
    "async_session": "app.core.database",
    "neo4j_driver": "app.core.database",
    "qdrant_client": "app.core.database",
    "redis_client": "app.core.database",
    "Base": "app.core.database",
    "get_db": "app.core.database",
    "init_db": "app.core.database",
    "close_db": "app.core.database",
    "verify_password": "app.core.security",
    "get_password_hash": "app.core.security",
    "create_access_token": "app.core.security",
    "decode_access_token": "app.core.security",
    "llm_manager": "app.core.llm",
    "LLMManager": "app.core.llm",
    "event_bus": "app.core.event_bus",
    "EventBus": "app.core.event_bus",
    "logger": "app.core.logger",
}

__all__ = list(_LAZY_EXPORTS)


def __getattr__(name: str) -> Any:
    module_path = _LAZY_EXPORTS.get(name)
    if module_path is None:
        raise AttributeError(f"module 'app.core' has no attribute '{name}'")
    import importlib

    return getattr(importlib.import_module(module_path), name)


def __dir__() -> list:
    return sorted(__all__)
