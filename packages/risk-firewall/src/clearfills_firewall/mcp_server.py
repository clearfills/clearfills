"""Clean JSON-RPC 2.0 / stdio MCP server for the ClearFills Pre-Trade Risk Firewall.

Exposes:
- `propose_trade`
- `get_kill_switch_status`
- `verify_audit_chain`

Allows Claude, Grok, Codex, Cursor, or any MCP-compatible host to invoke ClearFills
directly without custom glue code.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Optional, TextIO

from pydantic import ValidationError

from .models import PortfolioSnapshot, TradeProposal
from .server import FirewallService

MCP_PROTOCOL_VERSION = "2024-11-05"

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "propose_trade",
        "description": (
            "Submit a pre-trade proposal and current portfolio snapshot to the ClearFills "
            "deterministic risk firewall. Returns APPROVED with a single-use Ed25519 "
            "attestation or VETOED with exact policy reason codes."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal": {
                    "type": "object",
                    "description": "TradeProposal object (agent_id, venue, symbol, side, order_type, quantity, limit_price, stop_price, target_price, confidence, reasoning_trace, source_citations, strategy_id).",
                },
                "portfolio": {
                    "type": "object",
                    "description": "PortfolioSnapshot object (account_id, nav_usd, cash_usd, daily_pnl_usd, open_positions).",
                },
            },
            "required": ["proposal", "portfolio"],
        },
    },
    {
        "name": "get_kill_switch_status",
        "description": (
            "Return the current fail-closed kill-switch state. Missing or corrupt state "
            "always reports tripped=true."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
    {
        "name": "verify_audit_chain",
        "description": (
            "Verify the tamper-evident SHA-256 hash chain across all entries in the "
            "ClearFills append-only audit ledger."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {},
            "additionalProperties": False,
        },
    },
]


def _jsonrpc_result(req_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _jsonrpc_error(req_id: Any, code: int, message: str, data: Any = None) -> dict[str, Any]:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _tool_result(payload: Any, is_error: bool = False) -> dict[str, Any]:
    return {
        "content": [
            {
                "type": "text",
                "text": json.dumps(payload, indent=2, default=str),
            }
        ],
        "isError": is_error,
    }


def handle_jsonrpc_request(
    request: dict[str, Any],
    service: FirewallService,
) -> Optional[dict[str, Any]]:
    """Process a single JSON-RPC 2.0 MCP message and return a response dict (or None for notifications)."""
    method = request.get("method")
    req_id = request.get("id")
    params = request.get("params") or {}

    if not isinstance(method, str):
        return _jsonrpc_error(req_id, -32600, "Invalid Request: missing method")

    # Notifications have no `id` and expect no reply
    if method.startswith("notifications/"):
        return None

    if method == "initialize":
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "clearfills-risk-firewall",
                    "version": "0.1.0",
                },
            },
        )

    if method == "ping":
        return _jsonrpc_result(req_id, {})

    if method == "tools/list":
        return _jsonrpc_result(req_id, {"tools": TOOL_DEFINITIONS})

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}

        if tool_name == "propose_trade":
            try:
                proposal = TradeProposal.model_validate(arguments.get("proposal"))
                portfolio = PortfolioSnapshot.model_validate(arguments.get("portfolio"))
            except (ValidationError, TypeError) as exc:
                return _jsonrpc_result(
                    req_id,
                    _tool_result({"error": "VALIDATION_ERROR", "detail": str(exc)}, is_error=True),
                )
            decision = service.propose(proposal=proposal, portfolio=portfolio)
            return _jsonrpc_result(req_id, _tool_result(decision.model_dump(mode="json")))

        if tool_name == "get_kill_switch_status":
            state = service.kill_switch.status()
            return _jsonrpc_result(req_id, _tool_result(state.model_dump(mode="json")))

        if tool_name == "verify_audit_chain":
            res = service.verify_audit()
            return _jsonrpc_result(req_id, _tool_result(res.model_dump(mode="json")))

        return _jsonrpc_error(req_id, -32602, f"Unknown tool: {tool_name}")

    return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")


def run_stdio_server(
    service: FirewallService,
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
) -> None:
    """Run line-delimited JSON-RPC 2.0 MCP server loop over stdio."""
    for raw_line in stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
        except json.JSONDecodeError as exc:
            resp = _jsonrpc_error(None, -32700, f"Parse error: {exc}")
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
            continue

        if not isinstance(req, dict):
            resp = _jsonrpc_error(None, -32600, "Invalid Request: expected JSON object")
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()
            continue

        resp = handle_jsonrpc_request(req, service)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()


def main() -> None:
    data_dir = os.environ.get("CLEARFILLS_DATA_DIR", "./.clearfills_data")
    policy_path = os.environ.get("CLEARFILLS_POLICY_YAML")
    init_armed = os.environ.get("CLEARFILLS_INIT_ARMED", "0") == "1"
    service = FirewallService.from_data_dir(
        data_dir=data_dir,
        policy_path=policy_path,
        initialize_armed=init_armed,
    )
    run_stdio_server(service)


if __name__ == "__main__":
    main()
