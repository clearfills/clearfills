"""ClearFills Desk OS — 6-Agent AI Trading Desk powered by clearfills-firewall."""

from .ibkr import (
    LIVE_ENV_FLAG,
    LIVE_PORTS,
    PAPER_PORTS,
    ExecutionReceipt,
    IBKRExecutionAdapter,
    LiveExecutionSafetyError,
    validate_ibkr_connection,
    verify_connected_accounts,
)
from .runtime import DESK_ROLES, DeskConfig, DeskRuntime, IBKRConnectionConfig
from .telemetry import publish_arena_heartbeat, sanitize_text

__all__ = [
    "DESK_ROLES",
    "DeskConfig",
    "DeskRuntime",
    "ExecutionReceipt",
    "IBKRConnectionConfig",
    "IBKRExecutionAdapter",
    "LIVE_ENV_FLAG",
    "LIVE_PORTS",
    "LiveExecutionSafetyError",
    "PAPER_PORTS",
    "publish_arena_heartbeat",
    "sanitize_text",
    "validate_ibkr_connection",
    "verify_connected_accounts",
]
