"""Central level-based logger (standard library `logging`).

Env:
- LOG_LEVEL: DEBUG|INFO|WARNING|ERROR|CRITICAL (default: INFO)
"""

from __future__ import annotations

import logging
import os
from typing import Optional


def _level_from_env() -> int:
    raw = (os.getenv("LOG_LEVEL") or "INFO").upper().strip()
    return getattr(logging, raw, logging.INFO)


def get_logger(name: Optional[str] = None) -> logging.Logger:
    """Get a configured logger.

    This configures the root logger once (idempotent).
    """
    level = _level_from_env()
    root = logging.getLogger()
    if not getattr(root, "_agent_wallet_configured", False):
        logging.basicConfig(
            level=level,
            format="%(asctime)s %(levelname)s %(name)s - %(message)s",
        )
        setattr(root, "_agent_wallet_configured", True)
    root.setLevel(level)
    return logging.getLogger(name or "agent_wallet")

