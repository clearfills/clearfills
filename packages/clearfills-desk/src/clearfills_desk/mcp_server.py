"""End-to-end Broker Execution MCP server for ClearFills Desk OS (Paper & Live IBKR over Fly/Tailscale).

Tools exposed over JSON-RPC 2.0 stdio:
- `get_portfolio`: Live NAV, settled USD/CAD cash, buying power, positions, open orders (sanitized)
- `get_quote`: Live bid/ask/last/close/VWAP quote for a symbol
- `preview_order`: Runs `clearfills-firewall` `propose()` (including sleeve rules) + IBKR `whatIf`
  margin/commission preview, returning a single-use Ed25519 attestation ID & exact order summary
- `execute_attested_order`: Enforces `human_confirm_above_usd` threshold, verifies Ed25519 single-use
  attestation (`dispatch_check`), and routes limit/bracket order to the IBKR Gateway
- `list_open_orders`: Lists sanitized open orders (flagging protective stops)
- `cancel_order`: Cancels an open order while preserving protective-stop cancel guards
- `get_kill_switch_status` & `verify_audit_chain`: Direct firewall inspection
"""

from __future__ import annotations

import json
import os
import sys
from collections import OrderedDict
from pathlib import Path
from typing import Any, Optional, TextIO

from pydantic import ValidationError

from clearfills_firewall import PortfolioSnapshot, SignedAttestation, TradeProposal

from .ibkr import IBKRExecutionAdapter, LiveExecutionSafetyError
from .runtime import DeskConfig, DeskRuntime

MCP_PROTOCOL_VERSION = "2024-11-05"
_MAX_CACHED_ATTESTATIONS = 256

BROKER_TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "name": "get_portfolio",
        "description": (
            "Return live NAV, settled USD/CAD cash, buying power, positions, and open orders "
            "from the connected IBKR Gateway (account ID masked for safety)."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "get_quote",
        "description": "Return live snapshot bid, ask, last, close, and VWAP for a symbol from IBKR.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "symbol": {"type": "string", "description": "Ticker symbol (e.g. SGOV, VT, GOOG, NVDA)."},
                "exchange": {"type": "string", "default": "SMART"},
                "currency": {"type": "string", "default": "USD"},
            },
            "required": ["symbol"],
        },
    },
    {
        "name": "preview_order",
        "description": (
            "Evaluate a TradeProposal through clearfills-firewall (enforcing sleeve policies, risk caps, "
            "and kill-switch) plus IBKR whatIf margin/commission preview. Returns a single-use Ed25519 "
            "attestation_id and exact order_summary without submitting an order."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal": {
                    "type": "object",
                    "description": "TradeProposal object (agent_id, venue, symbol, side, order_type, quantity, limit_price, stop_price, target_price, confidence, reasoning_trace).",
                },
                "portfolio": {
                    "type": "object",
                    "description": "Optional PortfolioSnapshot override; when omitted, live portfolio is fetched from IBKR.",
                },
            },
            "required": ["proposal"],
        },
    },
    {
        "name": "execute_attested_order",
        "description": (
            "Verify the single-use Ed25519 attestation from preview_order and submit the limit/bracket "
            "order to the IBKR Gateway. Orders at or above human_confirm_above_usd require human_confirmed=true."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "proposal": {"type": "object"},
                "attestation_id": {"type": "string"},
                "attestation": {
                    "type": "object",
                    "description": "Optional full SignedAttestation JSON (otherwise resolved from preview_order cache by attestation_id).",
                },
                "human_confirmed": {
                    "type": "boolean",
                    "default": False,
                    "description": "Must be true after showing preview_order summary to the human when order notional >= human_confirm_above_usd.",
                },
            },
            "required": ["proposal", "attestation_id"],
        },
    },
    {
        "name": "list_open_orders",
        "description": "List all open IBKR orders (sanitized of raw account IDs, flagging protective stops).",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "cancel_order",
        "description": "Cancel an open IBKR order by order_id. Refuses to cancel protective stop-loss orders unless force_cancel_stop=true.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "order_id": {"type": "integer"},
                "force_cancel_stop": {"type": "boolean", "default": False},
            },
            "required": ["order_id"],
        },
    },
    {
        "name": "get_kill_switch_status",
        "description": "Return the current fail-closed ClearFills firewall kill-switch state.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
    },
    {
        "name": "verify_audit_chain",
        "description": "Verify the SHA-256 tamper-evident audit ledger across all firewall decisions.",
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
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
        "content": [{"type": "text", "text": json.dumps(payload, indent=2, default=str)}],
        "isError": is_error,
    }


class BrokerMCPServer:
    """Stateful MCP handler bridging ClearFills Firewall and IBKRExecutionAdapter."""

    def __init__(self, adapter: IBKRExecutionAdapter) -> None:
        self.adapter = adapter
        self.runtime = adapter.runtime
        self._attestation_cache: OrderedDict[str, tuple[SignedAttestation, float, dict[str, Any]]] = OrderedDict()

    def _cache_attestation(
        self,
        attestation: SignedAttestation,
        notional_usd: float,
        order_summary: dict[str, Any],
    ) -> None:
        self._attestation_cache[attestation.attestation_id] = (attestation, notional_usd, order_summary)
        self._attestation_cache.move_to_end(attestation.attestation_id)
        while len(self._attestation_cache) > _MAX_CACHED_ATTESTATIONS:
            self._attestation_cache.popitem(last=False)

    def _build_order_summary(
        self,
        proposal: TradeProposal,
        notional_usd: float,
        sleeve: str,
    ) -> dict[str, Any]:
        return {
            "execution_mode": self.adapter.execution_mode,
            "venue": proposal.venue,
            "symbol": proposal.symbol.upper(),
            "side": proposal.side.value,
            "quantity": proposal.quantity,
            "order_type": proposal.order_type.value,
            "limit_price": proposal.limit_price,
            "stop_price": proposal.stop_price,
            "target_price": proposal.target_price,
            "estimated_notional_usd": round(notional_usd, 2),
            "sleeve": sleeve,
            "agent_id": proposal.agent_id,
        }

    def handle_request(self, request: dict[str, Any]) -> Optional[dict[str, Any]]:
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
                        "name": f"clearfills-desk-broker-{self.adapter.execution_mode}",
                        "version": "0.1.0",
                    },
                },
            )
        if method == "ping":
            return _jsonrpc_result(req_id, {})
        if method == "tools/list":
            return _jsonrpc_result(req_id, {"tools": BROKER_TOOL_DEFINITIONS})
        if method == "tools/call":
            tool_name = params.get("name")
            arguments = params.get("arguments") or {}
            if not isinstance(tool_name, str):
                return _jsonrpc_error(req_id, -32602, "Missing tool name")
            return _jsonrpc_result(req_id, self._dispatch_tool(tool_name, arguments))
        return _jsonrpc_error(req_id, -32601, f"Method not found: {method}")

    def _dispatch_tool(self, tool_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        try:
            if tool_name == "get_portfolio":
                return _tool_result(self.adapter.get_portfolio())

            if tool_name == "get_quote":
                symbol = str(arguments.get("symbol", "")).strip()
                if not symbol:
                    return _tool_result({"error": "VALIDATION_ERROR", "detail": "symbol is required"}, is_error=True)
                return _tool_result(
                    self.adapter.get_quote(
                        symbol,
                        exchange=str(arguments.get("exchange", "SMART")),
                        currency=str(arguments.get("currency", "USD")),
                    )
                )

            if tool_name == "preview_order":
                try:
                    proposal = TradeProposal.model_validate(arguments.get("proposal"))
                except (ValidationError, TypeError) as exc:
                    return _tool_result({"error": "VALIDATION_ERROR", "detail": str(exc)}, is_error=True)

                if arguments.get("portfolio") is not None:
                    try:
                        portfolio = PortfolioSnapshot.model_validate(arguments["portfolio"])
                    except (ValidationError, TypeError) as exc:
                        return _tool_result({"error": "VALIDATION_ERROR", "detail": str(exc)}, is_error=True)
                else:
                    portfolio = self.adapter.build_portfolio_snapshot()

                decision = self.runtime.evaluate_proposal(proposal=proposal, portfolio=portfolio)
                notional_usd = float(decision.metrics.get("order_notional_usd") or 0.0)
                sleeve = str(decision.metrics.get("sleeve") or "active_trading")
                summary = self._build_order_summary(proposal, notional_usd, sleeve)

                if not decision.approved or decision.attestation is None:
                    return _tool_result(
                        {
                            "approved": False,
                            "status": decision.status.value,
                            "reason_codes": decision.reason_codes,
                            "reasons": decision.reasons,
                            "metrics": decision.metrics,
                            "order_summary": summary,
                        }
                    )

                what_if = self.adapter.what_if_order(proposal)
                threshold = self.runtime.config.human_confirm_above_usd
                requires_confirm = notional_usd >= threshold
                self._cache_attestation(decision.attestation, notional_usd, summary)

                return _tool_result(
                    {
                        "approved": True,
                        "status": decision.status.value,
                        "proposal_id": proposal.proposal_id,
                        "attestation_id": decision.attestation.attestation_id,
                        "expires_at": decision.attestation.expires_at.isoformat(),
                        "order_hash": decision.attestation.order_hash,
                        "metrics": decision.metrics,
                        "what_if": what_if,
                        "order_summary": summary,
                        "requires_human_confirmation": requires_confirm,
                        "human_confirm_above_usd": threshold,
                    }
                )

            if tool_name == "execute_attested_order":
                att_id = str(arguments.get("attestation_id", "")).strip()
                cached = self._attestation_cache.get(att_id)
                raw_proposal = arguments.get("proposal")
                if not isinstance(raw_proposal, dict):
                    return _tool_result({"error": "VALIDATION_ERROR", "detail": "proposal must be an object"}, is_error=True)

                if arguments.get("attestation") is not None:
                    try:
                        attestation = SignedAttestation.model_validate(arguments["attestation"])
                    except (ValidationError, TypeError) as exc:
                        return _tool_result({"error": "VALIDATION_ERROR", "detail": str(exc)}, is_error=True)
                    prop_payload = dict(raw_proposal)
                    prop_payload.setdefault("proposal_id", attestation.proposal_id)
                    try:
                        proposal = TradeProposal.model_validate(prop_payload)
                    except (ValidationError, TypeError) as exc:
                        return _tool_result({"error": "VALIDATION_ERROR", "detail": str(exc)}, is_error=True)
                    notional_usd = (proposal.limit_price or 0.0) * proposal.quantity
                    sleeve, _ = self.runtime.config.risk.resolve_sleeve(proposal.symbol)
                    summary = self._build_order_summary(proposal, notional_usd, sleeve)
                elif cached is not None:
                    attestation, notional_usd, summary = cached
                    prop_payload = dict(raw_proposal)
                    prop_payload.setdefault("proposal_id", attestation.proposal_id)
                    try:
                        proposal = TradeProposal.model_validate(prop_payload)
                    except (ValidationError, TypeError) as exc:
                        return _tool_result({"error": "VALIDATION_ERROR", "detail": str(exc)}, is_error=True)
                else:
                    return _tool_result(
                        {
                            "error": "UNKNOWN_ATTESTATION_ID",
                            "detail": f"Attestation {att_id!r} not found in preview cache. Call preview_order first.",
                        },
                        is_error=True,
                    )

                threshold = self.runtime.config.human_confirm_above_usd
                human_confirmed = bool(arguments.get("human_confirmed", False))
                if notional_usd >= threshold and not human_confirmed:
                    return _tool_result(
                        {
                            "error": "HUMAN_CONFIRMATION_REQUIRED",
                            "detail": (
                                f"Order notional ${notional_usd:,.2f} meets/exceeds human_confirm_above_usd "
                                f"(${threshold:,.2f}). Present the order_summary to the operator and re-call "
                                "execute_attested_order with human_confirmed=true."
                            ),
                            "attestation_id": attestation.attestation_id,
                            "order_summary": summary,
                        },
                        is_error=True,
                    )

                receipt = self.adapter.submit_attested_order(proposal=proposal, attestation=attestation)
                self._attestation_cache.pop(attestation.attestation_id, None)
                return _tool_result(receipt.model_dump(mode="json"))

            if tool_name == "list_open_orders":
                return _tool_result({"open_orders": self.adapter.list_open_orders()})

            if tool_name == "cancel_order":
                order_id = arguments.get("order_id")
                if order_id is None:
                    return _tool_result({"error": "VALIDATION_ERROR", "detail": "order_id is required"}, is_error=True)
                return _tool_result(
                    self.adapter.cancel_order(
                        int(order_id),
                        force_cancel_stop=bool(arguments.get("force_cancel_stop", False)),
                    )
                )

            if tool_name == "get_kill_switch_status":
                return _tool_result(self.runtime.firewall.kill_switch.status().model_dump(mode="json"))

            if tool_name == "verify_audit_chain":
                return _tool_result(self.runtime.firewall.verify_audit().model_dump(mode="json"))

            return _tool_result({"error": f"Unknown tool: {tool_name}"}, is_error=True)
        except LiveExecutionSafetyError as exc:
            return _tool_result({"error": "SAFETY_GUARD_BLOCKED", "detail": str(exc)}, is_error=True)
        except Exception as exc:
            return _tool_result({"error": "BROKER_EXECUTION_ERROR", "detail": str(exc)}, is_error=True)


def run_broker_stdio_server(
    server: BrokerMCPServer,
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
        resp = server.handle_request(req)
        if resp is not None:
            stdout.write(json.dumps(resp) + "\n")
            stdout.flush()


def main() -> None:
    config_path = os.environ.get("CLEARFILLS_DESK_CONFIG", "").strip()
    if not config_path:
        sys.stderr.write("CLEARFILLS_DESK_CONFIG=/path/to/desk.yaml is required.\n")
        sys.exit(2)
    state_dir = os.environ.get("CLEARFILLS_DESK_STATE", "./.clearfills_desk")
    cfg = DeskConfig.from_yaml(Path(config_path))
    runtime = DeskRuntime(cfg, state_dir=state_dir)
    adapter = IBKRExecutionAdapter(runtime)
    server = BrokerMCPServer(adapter)
    run_broker_stdio_server(server)


if __name__ == "__main__":
    main()
