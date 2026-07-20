"""Structured logging.

Note on `cache_logger_on_first_use`: it must stay False here. Around forty
modules share the single `logger` object exported below. With caching enabled,
structlog's stdlib LoggerFactory resolved the caller's module name exactly once
and then froze it, so every log line in the entire application was attributed to
whichever module happened to log first (in practice `app.ml.sequence_model`).
Disabling the cache makes the factory re-resolve the calling frame per call, so
`logger_name` is correct. The cost is one frame inspection per log call, which
is not measurable against the I/O these handlers do.

Prefer `get_logger(__name__)` in new modules - it binds the name explicitly and
avoids the frame walk entirely.
"""

import logging
import sys

import structlog

from app.core.config import settings

logging.basicConfig(
    format="%(message)s",
    stream=sys.stdout,
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
)

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        structlog.dev.ConsoleRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=False,
)


def get_logger(name: str = None):
    return structlog.get_logger(name)


logger = structlog.get_logger()
