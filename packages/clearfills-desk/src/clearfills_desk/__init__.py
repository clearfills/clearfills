"""ClearFills Desk OS — 6-Agent AI Trading Desk powered by clearfills-firewall."""

from .runtime import DESK_ROLES, DeskConfig, DeskRuntime
from .telemetry import sanitize_text, publish_arena_heartbeat

__all__ = [
    "DESK_ROLES",
    "DeskConfig",
    "DeskRuntime",
    "sanitize_text",
    "publish_arena_heartbeat",
]
