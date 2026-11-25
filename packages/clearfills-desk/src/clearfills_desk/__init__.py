"""ClearFills Desk OS — 6-Agent AI Trading Desk powered by clearfills-firewall."""

from .enclave_client import EnclaveClientError, RemoteEnclaveFirewallClient
from .ibkr import (
    LIVE_ENV_FLAG,
    LIVE_PORTS,
    PAPER_PORTS,
    PAPER_TAILNET_PORTS,
    ExecutionReceipt,
    IBKRExecutionAdapter,
    LiveExecutionSafetyError,
    mask_account_id,
    validate_ibkr_connection,
    verify_connected_accounts,
)
from .mcp_server import BROKER_TOOL_DEFINITIONS, BrokerMCPServer, run_broker_stdio_server
from .runtime import DESK_ROLES, DeskConfig, DeskRuntime, IBKRConnectionConfig
from .telemetry import publish_arena_heartbeat, sanitize_text
from .worker import (
    ApprovalWorker,
    CloudHTTPError,
    compute_approval_hash,
    verify_local_webauthn_cosign,
    verify_operator_passkey_cosignature,
)

__all__ = [
    "ApprovalWorker",
    "BROKER_TOOL_DEFINITIONS",
    "BrokerMCPServer",
    "CloudHTTPError",
    "DESK_ROLES",
    "DeskConfig",
    "DeskRuntime",
    "EnclaveClientError",
    "ExecutionReceipt",
    "IBKRConnectionConfig",
    "IBKRExecutionAdapter",
    "LIVE_ENV_FLAG",
    "LIVE_PORTS",
    "LiveExecutionSafetyError",
    "PAPER_PORTS",
    "PAPER_TAILNET_PORTS",
    "RemoteEnclaveFirewallClient",
    "compute_approval_hash",
    "mask_account_id",
    "publish_arena_heartbeat",
    "run_broker_stdio_server",
    "sanitize_text",
    "validate_ibkr_connection",
    "verify_connected_accounts",
    "verify_local_webauthn_cosign",
    "verify_operator_passkey_cosignature",
]
