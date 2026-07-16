#!/usr/bin/env python3
"""
Central loguru configuration for the YARA rule pipeline.

Designed for CI/CD: level is driven by the ``LOG_LEVEL`` env var (default
``INFO``); INFO/DEBUG go to stdout and WARNING+ go to stderr so a pipeline can
capture the two streams independently. Color is auto-enabled only on a TTY, so
CI logs stay plain and grep-friendly. ``diagnose`` is off to avoid leaking
local variable values into logs.

Every CLI entrypoint calls ``setup_logging()`` once at the top of ``main()``.
Library code simply imports ``logger`` from loguru; if an importer never calls
``setup_logging()``, loguru's built-in stderr handler is a safe fallback.
"""

import os
import sys

from loguru import logger

_CONFIGURED = False

# Time | LEVEL | message — no module/line noise; parseable and human-readable.
_FORMAT = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | "
    "<level>{message}</level>"
)


def setup_logging(force: bool = False):
    """Configure loguru sinks. Idempotent unless ``force`` is set.

    Level comes from ``LOG_LEVEL`` (default INFO). INFO and DEBUG are routed to
    stdout; WARNING, ERROR and CRITICAL to stderr. Returns the ``logger``.
    """
    global _CONFIGURED
    if _CONFIGURED and not force:
        return logger

    level = os.environ.get("LOG_LEVEL", "INFO").upper()

    logger.remove()
    logger.add(
        sys.stdout,
        level=level,
        format=_FORMAT,
        filter=lambda record: record["level"].no < logger.level("WARNING").no,
        backtrace=False,
        diagnose=False,
    )
    logger.add(
        sys.stderr,
        level="WARNING",
        format=_FORMAT,
        backtrace=False,
        diagnose=False,
    )

    _CONFIGURED = True
    return logger
