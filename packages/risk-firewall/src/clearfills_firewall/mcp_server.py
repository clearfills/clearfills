"""Clean JSON-RPC 2.0 / stdio MCP server for ClearFills (Local Firewall + Remote Cloud Trading OS).

Local mode (default, zero network calls):
- `propose_trade`
- `get_kill_switch_status`
- `verify_audit_chain`

Cloud Trading OS mode (when `CLEARFILLS_API_KEY=cf_sk_...` is set):
- All 3 firewall tools routed to `https://clearfills-api.fly.dev/api/v1/cloud/*`
- `manage_watchlist` (list / upsert / delete per-tenant tickers)
- `save_research_note` & `list_research_notes`
- `log_trade_journal` & `list_trade_journal`
- `run_backtest` (deterministic cost-adjusted CAGR / Sharpe / Deflated Sharpe Ratio receipt)
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from typing import Any, Callable, Optional, TextIO

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
                    "description": "PortfolioSnapshot object (account_id, nav_usd, cash_usd, daily_pnl_usd, session_entries, open_positions).",
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

CLOUD_TOOL_DEFINITIONS: list[dict[str, Any]] = TOOL_DEFINITIONS + [
    {
        "name": "manage_watchlist",
        "description": "List, upsert, or delete tickers in your private ClearFills tenant watchlist.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "action": {"type": "string", "enum": ["list", "upsert", "delete"]},
                "symbol": {"type": "string"},
                "thesis": {"type": "string"},
                "tags": {"type": "array", "items": {"type": "string"}},
                "status": {"type": "string", "enum": ["watching", "candidate", "active", "archived"]},
            },
            "required": ["action"],
        },
    },
    {
        "name": "save_research_note",
        "description": "Store a structured research note with SEC/URL citations in your private ClearFills workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "symbols": {"type": "array", "items": {"type": "string"}},
                "body": {"type": "string"},
                "citations": {"type": "array", "items": {"type": "string"}},
                "verdict": {"type": "string", "enum": ["OPEN", "VERIFIED", "FALSIFIED", "PENDING"]},
                "agent_id": {"type": "string"},
            },
            "required": ["title", "body"],
        },
    },
    {
        "name": "list_research_notes",
        "description": "List recent research notes from your private ClearFills workspace.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 200}},
        },
    },
    {
        "name": "log_trade_journal",
        "description": "Append a trade entry, exit, P&L, attestation ID, and lessons to your private ClearFills journal.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string"},
                "side": {"type": "string", "enum": ["BUY", "SELL"]},
                "quantity": {"type": "number"},
                "entry_price": {"type": "number"},
                "exit_price": {"type": "number"},
                "stop_price": {"type": "number"},
                "realized_pnl_usd": {"type": "number"},
                "attestation_id": {"type": "string"},
                "execution_mode": {"type": "string", "enum": ["paper", "live", "shadow"]},
                "rationale": {"type": "string"},
                "lessons": {"type": "string"},
                "agent_id": {"type": "string"},
            },
            "required": ["symbol", "side", "quantity", "entry_price"],
        },
    },
    {
        "name": "list_trade_journal",
        "description": "List recent entries from your private ClearFills trade journal.",
        "inputSchema": {
            "type": "object",
            "properties": {"limit": {"type": "integer", "minimum": 1, "maximum": 500}},
        },
    },
    {
        "name": "run_backtest",
        "description": "Run a deterministic cost-adjusted backtest and Bailey-Lopez de Prado Deflated Sharpe Ratio (DSR) receipt in ClearFills Cloud.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "strategy_name": {"type": "string"},
                "symbol": {"type": "string"},
                "daily_returns": {"type": "array", "items": {"type": "number"}},
                "benchmark_returns": {"type": "array", "items": {"type": "number"}},
                "cost_bps_per_day": {"type": "number"},
                "n_trials": {"type": "integer", "minimum": 1},
            },
            "required": ["strategy_name", "daily_returns"],
        },
    },
]


class CloudMCPClient:
    """Thin stdlib HTTP client forwarding MCP tool calls to ClearFills Managed Cloud."""

    def __init__(
        self,
        api_key: str,
        api_base: str = "https://clearfills-api.fly.dev",
        transport: Optional[Callable[[str, str, Optional[dict[str, Any]]], Any]] = None,
    ) -> None:
        self.api_key = api_key.strip()
        self.api_base = api_base.rstrip("/")
        self._transport = transport

    def request(self, method: str, path: str, body: Optional[dict[str, Any]] = None) -> Any:
        if self._transport is not None:
            return self._transport(method, path, body)
        url = f"{self.api_base}{path}"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        data = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"HTTP {exc.code}: {detail}") from exc


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


def _handle_cloud_tool_call(
    tool_name: str,
    arguments: dict[str, Any],
    cloud: CloudMCPClient,
) -> dict[str, Any]:
    try:
        if tool_name == "propose_trade":
            res = cloud.request(
                "POST",
                "/api/v1/cloud/propose",
                {"proposal": arguments.get("proposal"), "portfolio": arguments.get("portfolio")},
            )
            return _tool_result(res)
        if tool_name == "get_kill_switch_status":
            return _tool_result(cloud.request("GET", "/api/v1/cloud/me"))
        if tool_name == "verify_audit_chain":
            return _tool_result(cloud.request("GET", "/api/v1/cloud/audit"))
        if tool_name == "manage_watchlist":
            action = arguments.get("action")
            if action == "list":
                return _tool_result(cloud.request("GET", "/api/v1/cloud/watchlists"))
            if action == "upsert":
                body = {k: v for k, v in arguments.items() if k != "action"}
                return _tool_result(cloud.request("POST", "/api/v1/cloud/watchlists", body))
            if action == "delete":
                sym = str(arguments.get("symbol", "")).strip().upper()
                return _tool_result(cloud.request("DELETE", f"/api/v1/cloud/watchlists/{sym}"))
            return _tool_result({"error": f"Unknown watchlist action: {action}"}, is_error=True)
        if tool_name == "save_research_note":
            return _tool_result(cloud.request("POST", "/api/v1/cloud/notes", arguments))
        if tool_name == "list_research_notes":
            limit = int(arguments.get("limit", 50))
            return _tool_result(cloud.request("GET", f"/api/v1/cloud/notes?limit={limit}"))
        if tool_name == "log_trade_journal":
            return _tool_result(cloud.request("POST", "/api/v1/cloud/journal", arguments))
        if tool_name == "list_trade_journal":
            limit = int(arguments.get("limit", 100))
            return _tool_result(cloud.request("GET", f"/api/v1/cloud/journal?limit={limit}"))
        if tool_name == "run_backtest":
            return _tool_result(cloud.request("POST", "/api/v1/cloud/backtests", arguments))
        return _tool_result({"error": f"Unknown tool: {tool_name}"}, is_error=True)
    except Exception as exc:
        return _tool_result({"error": "CLOUD_API_ERROR", "detail": str(exc)}, is_error=True)


def handle_jsonrpc_request(
    request: dict[str, Any],
    service: Optional[FirewallService],
    *,
    cloud_client: Optional[CloudMCPClient] = None,
) -> Optional[dict[str, Any]]:
    """Process a single JSON-RPC 2.0 MCP message and return a response dict (or None for notifications)."""
    method = request.get("method")
    req_id = request.get("id")
    params = request.get("params") or {}

    if not isinstance(method, str):
        return _jsonrpc_error(req_id, -32600, "Invalid Request: missing method")

    if method.startswith("notifications/"):
        return None

    if method == "initialize":
        return _jsonrpc_result(
            req_id,
            {
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "clearfills-trading-os" if cloud_client else "clearfills-risk-firewall",
                    "version": "0.3.0",
                },
            },
        )

    if method == "ping":
        return _jsonrpc_result(req_id, {})

    if method == "tools/list":
        tools = CLOUD_TOOL_DEFINITIONS if cloud_client is not None else TOOL_DEFINITIONS
        return _jsonrpc_result(req_id, {"tools": tools})

    if method == "tools/call":
        tool_name = params.get("name")
        arguments = params.get("arguments") or {}

        if cloud_client is not None:
            if not isinstance(tool_name, str):
                return _jsonrpc_error(req_id, -32602, "Missing tool name")
            return _jsonrpc_result(req_id, _handle_cloud_tool_call(tool_name, arguments, cloud_client))

        assert service is not None
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
    service: Optional[FirewallService],
    stdin: TextIO = sys.stdin,
    stdout: TextIO = sys.stdout,
    *,
    cloud_client: Optional[CloudMCPClient] = None,
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

        resp = handle_jsonrpc_request(req, service, cloud_client=cloud_client)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()


def main() -> None:
    api_key = os.environ.get("CLEARFILLS_API_KEY", "").strip()
    if api_key or "--cloud" in sys.argv[1:]:
        if not api_key:
            sys.stderr.write("CLEARFILLS_API_KEY is required for --cloud mode.\n")
            sys.exit(2)
        api_url = os.environ.get("CLEARFILLS_API_URL", "https://clearfills-api.fly.dev")
        run_stdio_server(None, cloud_client=CloudMCPClient(api_key=api_key, api_base=api_url))
        return

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
