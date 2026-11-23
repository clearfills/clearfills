"""Tests for v0.3.0 authoritative hardening (0600 key perms, cross-process nonce lock) and Cloud MCP."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

from clearfills_firewall import Side, TradeProposal
from clearfills_firewall.attestation import AttestationAuthority
from clearfills_firewall.mcp_server import CloudMCPClient, handle_jsonrpc_request


def test_private_key_created_with_0600_and_cross_process_nonce_replay_blocked(tmp_path: Path) -> None:
    pem_path = tmp_path / "ed25519_key.pem"
    nonces_path = tmp_path / "spent_nonces.json"

    auth1 = AttestationAuthority.from_pem_file(pem_path, spent_nonces_path=nonces_path)
    mode = stat.S_IMODE(os.stat(pem_path).st_mode)
    assert mode == 0o600

    # Second independent authority instance simulating a separate OS process
    auth2 = AttestationAuthority.from_pem_file(pem_path, spent_nonces_path=nonces_path)
    assert auth1.key_id == auth2.key_id

    proposal = TradeProposal(
        agent_id="desk-proc-1",
        venue="ibkr",
        symbol="AAPL",
        side=Side.BUY,
        quantity=10.0,
        limit_price=200.0,
        stop_price=190.0,
    )
    att = auth1.issue(proposal)

    # Process 1 consumes the nonce
    ok1, reason1 = auth1.verify_and_consume(att, proposal)
    assert ok1 is True and reason1 == "OK"

    # Process 2 MUST see the persisted nonce under flock and reject replay
    ok2, reason2 = auth2.verify_and_consume(att, proposal)
    assert ok2 is False and reason2 == "ATTESTATION_REPLAY_DETECTED"


def test_cloud_mcp_mode_exposes_trading_os_tools() -> None:
    calls: list[tuple[str, str, object]] = []

    def fake_transport(method: str, path: str, body: object) -> dict:
        calls.append((method, path, body))
        return {"ok": True, "path": path}

    cloud = CloudMCPClient(api_key="cf_sk_test_123", transport=fake_transport)

    listed = handle_jsonrpc_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, None, cloud_client=cloud)
    assert listed is not None
    names = {t["name"] for t in listed["result"]["tools"]}
    assert {
        "propose_trade",
        "manage_watchlist",
        "save_research_note",
        "log_trade_journal",
        "run_backtest",
    }.issubset(names)

    res = handle_jsonrpc_request(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "manage_watchlist",
                "arguments": {"action": "upsert", "symbol": "NVDA", "thesis": "AI demand"},
            },
        },
        None,
        cloud_client=cloud,
    )
    assert res is not None
    payload = json.loads(res["result"]["content"][0]["text"])
    assert payload["ok"] is True
    assert calls[0][0] == "POST" and calls[0][1] == "/api/v1/cloud/watchlists"


def test_cloud_mcp_approvals_mandates_and_track_record_tools() -> None:
    calls: list[tuple[str, str, object]] = []

    def fake_transport(method: str, path: str, body: object) -> dict:
        calls.append((method, path, body))
        return {"ok": True, "method": method, "path": path}

    cloud = CloudMCPClient(api_key="cf_sk_test_456", transport=fake_transport)

    listed = handle_jsonrpc_request({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}, None, cloud_client=cloud)
    assert listed is not None
    names = {t["name"] for t in listed["result"]["tools"]}
    assert {
        "submit_for_approval",
        "list_approvals",
        "list_mandates",
        "evaluate_mandates",
        "get_track_record",
    }.issubset(names)

    def _call(tool_name: str, arguments: dict | None = None) -> dict:
        resp = handle_jsonrpc_request(
            {
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/call",
                "params": {"name": tool_name, "arguments": arguments or {}},
            },
            None,
            cloud_client=cloud,
        )
        assert resp is not None
        assert resp["result"]["isError"] is False
        return json.loads(resp["result"]["content"][0]["text"])

    _call("submit_for_approval", {"symbol": "SGOV", "side": "BUY", "quantity": 500, "notional_usd": 50125.0})
    _call("list_approvals", {"status": "pending", "limit": 20})
    _call("list_mandates")
    _call("evaluate_mandates", {"entity": "personal", "portfolio": {"nav_usd": 500000.0}})
    _call("get_track_record", {"agent_id": "swing-bot", "limit": 50})

    assert calls[0] == (
        "POST",
        "/api/v1/cloud/approvals",
        {"symbol": "SGOV", "side": "BUY", "quantity": 500, "notional_usd": 50125.0},
    )
    assert calls[1] == ("GET", "/api/v1/cloud/approvals?status=pending&limit=20", None)
    assert calls[2] == ("GET", "/api/v1/cloud/mandates", None)
    assert calls[3] == (
        "POST",
        "/api/v1/cloud/mandates/evaluate",
        {"entity": "personal", "portfolio": {"nav_usd": 500000.0}},
    )
    assert calls[4] == ("GET", "/api/v1/cloud/track-record?agent_id=swing-bot&limit=50", None)
