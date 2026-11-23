"""Tests for upstream agent shims, FastAPI HTTP endpoints, and MCP JSON-RPC server."""

from __future__ import annotations

import io
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from clearfills_firewall.adapters import (
    from_ai_hedge_fund_signal,
    from_tradingagents_decision,
)
from clearfills_firewall.mcp_server import handle_jsonrpc_request, run_stdio_server
from clearfills_firewall.models import Side
from clearfills_firewall.server import FirewallService, create_app


def _sample_portfolio_dict() -> dict:
    return {
        "account_id": "DU0000000",
        "nav_usd": 100_000.0,
        "cash_usd": 85_000.0,
        "daily_pnl_usd": 250.0,
        "open_positions": [],
    }


def _sample_proposal_dict() -> dict:
    return {
        "agent_id": "grok-alpha-v2",
        "venue": "ibkr",
        "venue_type": "EQUITY",
        "symbol": "MSFT",
        "side": "BUY",
        "order_type": "LIMIT",
        "quantity": 25.0,
        "limit_price": 400.0,
        "stop_price": 380.0,
        "target_price": 450.0,
        "reasoning_trace": "Cloud acceleration and clean pullback to 50DMA.",
        "source_citations": ["https://example.com/msft-q3"],
        "confidence": 0.62,
        "strategy_id": "swing_breakout",
    }


def test_tradingagents_adapter_maps_and_evaluates(tmp_path: Path) -> None:
    payload = {
        "company_of_interest": "NVDA",
        "final_trade_decision": "FINAL TRANSACTION PROPOSAL: **BUY**",
        "investment_debate_state": {
            "bull_history": "Data center GPU backlog remains sold out through next year.",
            "bear_history": "Gross margin compression risk from custom ASICs.",
            "judge_decision": "Bull case dominates on near-term earnings visibility.",
        },
        "risk_debate_state": {
            "judge_decision": "Approve 0.5% risk allocation with tight stop.",
        },
        "market_report": "Strong uptrend above 20/50 EMA",
        "fundamentals_report": "Revenue growth +78% YoY",
        "quantity": 50,
        "price": 120.0,
        "stop_price": 112.0,
        "target_price": 144.0,
        "confidence": 0.65,
        "venue": "ibkr",
    }
    proposal = from_tradingagents_decision(payload)
    assert proposal.symbol == "NVDA"
    assert proposal.side == Side.BUY
    assert proposal.agent_id == "tradingagents-orchestrator"
    assert "Bull Case:" in proposal.reasoning_trace
    assert "Bear Case:" in proposal.reasoning_trace
    assert "tradingagents:market_report" in proposal.source_citations

    service = FirewallService.from_data_dir(tmp_path, initialize_armed=True)
    from clearfills_firewall.models import PortfolioSnapshot

    decision = service.propose(proposal, PortfolioSnapshot.model_validate(_sample_portfolio_dict()))
    assert decision.approved is True
    assert decision.attestation is not None

    # HOLD decision should raise ValueError (not an actionable order)
    with pytest.raises(ValueError):
        from_tradingagents_decision({"company_of_interest": "NVDA", "final_trade_decision": "HOLD"})


def test_ai_hedge_fund_adapter_maps_and_evaluates(tmp_path: Path) -> None:
    payload = {
        "ticker": "GOOGL",
        "action": "buy",
        "quantity": 60,
        "confidence": 72,  # 0..100 scale
        "price": 175.0,
        "stop_price": 165.0,
        "target_price": 205.0,
        "reasoning": "Compelling FCF multiple with search + cloud durability.",
        "analyst_signals": {
            "warren_buffett_agent": {
                "signal": "bullish",
                "confidence": 80,
                "reasoning": "Durable moat and high ROIC.",
            },
            "michael_burry_agent": {
                "signal": "neutral",
                "confidence": 50,
                "reasoning": "Capex cycle needs monitoring.",
            },
        },
        "venue": "alpaca",
    }
    proposal = from_ai_hedge_fund_signal(payload)
    assert proposal.symbol == "GOOGL"
    assert proposal.side == Side.BUY
    assert proposal.confidence == pytest.approx(0.72)
    assert "ai-hedge-fund:warren_buffett_agent" in proposal.source_citations
    assert "[warren_buffett_agent]" in proposal.reasoning_trace

    service = FirewallService.from_data_dir(tmp_path, initialize_armed=True)
    from clearfills_firewall.models import PortfolioSnapshot

    decision = service.propose(proposal, PortfolioSnapshot.model_validate(_sample_portfolio_dict()))
    assert decision.approved is True
    assert decision.attestation is not None


def test_fastapi_integration_end_to_end(tmp_path: Path) -> None:
    service = FirewallService.from_data_dir(tmp_path, initialize_armed=True)
    app = create_app(service)
    client = TestClient(app)

    # 1. Health check
    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["kill_switch_tripped"] is False
    assert health.json()["audit_chain_valid"] is True

    # 2. Propose valid trade -> APPROVED + signed attestation
    proposal_data = _sample_proposal_dict()
    portfolio_data = _sample_portfolio_dict()
    resp = client.post("/v1/propose", json={"proposal": proposal_data, "portfolio": portfolio_data})
    assert resp.status_code == 200
    dec = resp.json()
    assert dec["approved"] is True
    assert dec["attestation"] is not None
    attestation = dec["attestation"]

    # Must include proposal_id generated by model if not supplied in request
    bound_proposal = dict(proposal_data)
    bound_proposal["proposal_id"] = dec["proposal_id"]

    # 3. Dispatch check with tampered quantity -> 403 ORDER_HASH_MISMATCH
    tampered = dict(bound_proposal)
    tampered["quantity"] = 250.0
    dc_tampered = client.post(
        "/v1/dispatch-check",
        json={"attestation": attestation, "proposal": tampered},
    )
    assert dc_tampered.status_code == 403
    assert dc_tampered.json()["allowed"] is False
    assert dc_tampered.json()["reason"] == "ORDER_HASH_MISMATCH"

    # 4. Dispatch check with exact bound proposal -> 200 OK
    dc_ok = client.post(
        "/v1/dispatch-check",
        json={"attestation": attestation, "proposal": bound_proposal},
    )
    assert dc_ok.status_code == 200
    assert dc_ok.json()["allowed"] is True
    assert dc_ok.json()["reason"] == "OK"

    # 5. Replay same attestation -> 403 ATTESTATION_REPLAY_DETECTED
    dc_replay = client.post(
        "/v1/dispatch-check",
        json={"attestation": attestation, "proposal": bound_proposal},
    )
    assert dc_replay.status_code == 403
    assert dc_replay.json()["reason"] == "ATTESTATION_REPLAY_DETECTED"

    # 6. Trip kill switch -> subsequent proposal VETOED
    trip = client.post(
        "/v1/killswitch/trip",
        json={"reason": "Abnormal slippage detected", "actor": "ops-admin"},
    )
    assert trip.status_code == 200
    assert trip.json()["tripped"] is True

    ks_status = client.get("/v1/killswitch/status")
    assert ks_status.status_code == 200
    assert ks_status.json()["tripped"] is True

    vetoed = client.post("/v1/propose", json={"proposal": proposal_data, "portfolio": portfolio_data})
    assert vetoed.status_code == 200
    assert vetoed.json()["approved"] is False
    assert "KILL_SWITCH_TRIPPED" in vetoed.json()["reason_codes"]

    # 7. Reset kill switch -> re-armed
    reset = client.post(
        "/v1/killswitch/reset",
        json={"reason": "Venue latency normalized", "approver": "cro-alice"},
    )
    assert reset.status_code == 200
    assert reset.json()["tripped"] is False

    # 8. Verify audit chain -> valid
    verify = client.get("/v1/audit/verify")
    assert verify.status_code == 200
    assert verify.json()["valid"] is True
    assert verify.json()["entry_count"] >= 6


def test_mcp_jsonrpc_stdio_server(tmp_path: Path) -> None:
    service = FirewallService.from_data_dir(tmp_path, initialize_armed=True)

    # Direct handle_jsonrpc_request tests
    init_resp = handle_jsonrpc_request({"jsonrpc": "2.0", "id": 1, "method": "initialize"}, service)
    assert init_resp is not None
    assert init_resp["result"]["serverInfo"]["name"] == "clearfills-risk-firewall"

    list_resp = handle_jsonrpc_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, service)
    assert list_resp is not None
    tool_names = {t["name"] for t in list_resp["result"]["tools"]}
    assert tool_names == {"propose_trade", "get_kill_switch_status", "verify_audit_chain"}

    # Full stdio loop test
    requests = [
        {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "get_kill_switch_status", "arguments": {}}},
        {
            "jsonrpc": "2.0",
            "id": 11,
            "method": "tools/call",
            "params": {
                "name": "propose_trade",
                "arguments": {
                    "proposal": _sample_proposal_dict(),
                    "portfolio": _sample_portfolio_dict(),
                },
            },
        },
        {"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "verify_audit_chain", "arguments": {}}},
    ]
    stdin = io.StringIO("\n".join(json.dumps(r) for r in requests) + "\n")
    stdout = io.StringIO()
    run_stdio_server(service, stdin=stdin, stdout=stdout)

    responses = [json.loads(line) for line in stdout.getvalue().splitlines() if line.strip()]
    assert len(responses) == 3

    ks_payload = json.loads(responses[0]["result"]["content"][0]["text"])
    assert ks_payload["tripped"] is False

    propose_payload = json.loads(responses[1]["result"]["content"][0]["text"])
    assert propose_payload["approved"] is True
    assert propose_payload["attestation"] is not None

    audit_payload = json.loads(responses[2]["result"]["content"][0]["text"])
    assert audit_payload["valid"] is True
    assert audit_payload["entry_count"] == 1
