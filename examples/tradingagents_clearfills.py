"""Drop-in ClearFills wrapper for TauricResearch/TradingAgents.

Gates TradingAgents' final trade decision behind ClearFills' deterministic
pre-trade risk firewall (limit-only, mandatory stop-loss, notional cap, and
120s Ed25519 attestation) and queues approved orders to the ClearFills Cloud
1-Tap Approval Inbox for Touch ID sign-off before IBKR or Alpaca execution.

Run standalone (zero API keys required):
    python examples/tradingagents_clearfills.py --dry-run

Queue into ClearFills Cloud 1-Tap Approval Inbox:
    export CLEARFILLS_API_KEY="cf_sk_..."
    python examples/tradingagents_clearfills.py
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import urllib.request
from pathlib import Path
from typing import Any

from clearfills_firewall import (
    FirewallService,
    PortfolioSnapshot,
    RiskDecision,
    RiskPolicy,
    TradeProposal,
    default_allocation_sleeves,
    from_tradingagents_decision,
)

CLOUD_API_URL = os.environ.get("CLEARFILLS_API_URL", "https://clearfills-api.fly.dev").rstrip("/")


def queue_to_approval_inbox(
    proposal: TradeProposal,
    decision: RiskDecision,
    *,
    api_key: str,
    dry_run: bool,
) -> dict[str, Any]:
    """Queue an Ed25519-attested proposal for 1-tap Touch ID sign-off."""
    assert decision.approved and decision.attestation is not None
    payload = {
        "symbol": proposal.symbol,
        "side": proposal.side.value,
        "quantity": proposal.quantity,
        "order_type": proposal.order_type.value,
        "limit_price": proposal.limit_price,
        "stop_price": proposal.stop_price,
        "target_price": proposal.target_price,
        "notional_usd": round((proposal.limit_price or 0.0) * proposal.quantity, 2),
        "attestation_id": decision.attestation.attestation_id,
        "proposal_id": proposal.proposal_id,
        "agent_id": proposal.agent_id,
        "venue": proposal.venue,
        "reasoning_trace": proposal.reasoning_trace,
    }
    if dry_run or not api_key:
        return {"status": "dry_run_queued", "endpoint": f"{CLOUD_API_URL}/api/v1/cloud/approvals", "payload": payload}

    req = urllib.request.Request(
        url=f"{CLOUD_API_URL}/api/v1/cloud/approvals",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def run(dry_run: bool) -> None:
    policy = RiskPolicy(
        max_risk_per_trade_pct=1.0,
        max_open_positions=10,
        max_total_heat_pct=6.0,
        max_daily_loss_pct=2.0,
        require_stop_loss=True,
        max_order_notional_usd=25_000.0,
        allow_shorting=False,
        sleeves=default_allocation_sleeves(),
    )
    portfolio = PortfolioSnapshot(
        account_id="DU1234567", nav_usd=100_000.0, cash_usd=50_000.0, daily_pnl_usd=0.0, session_entries=0, open_positions=[]
    )

    # Representative final decision dicts from TauricResearch/TradingAgents
    ta_decisions: list[dict[str, Any]] = [
        {
            "company_of_interest": "NVDA",
            "final_trade_decision": "FINAL TRANSACTION PROPOSAL: **BUY** NVDA",
            "venue": "ibkr",
            "order_type": "MARKET",
            "quantity": 100,
            "limit_price": None,
            "stop_price": None,
            "agent_id": "tradingagents-orchestrator",
        },
        {
            "company_of_interest": "MSFT",
            "final_trade_decision": "FINAL TRANSACTION PROPOSAL: **BUY** MSFT",
            "investment_debate_state": {"judge_decision": "Sized long entry with hard stop below support."},
            "risk_debate_state": {"judge_decision": "Limit-only execution, 0.5% NAV risk."},
            "venue": "ibkr",
            "order_type": "LIMIT",
            "quantity": 25,
            "limit_price": 400.00,
            "stop_price": 380.00,
            "target_price": 440.00,
            "confidence": 0.72,
            "agent_id": "tradingagents-orchestrator",
        },
    ]

    api_key = os.environ.get("CLEARFILLS_API_KEY", "").strip()
    with tempfile.TemporaryDirectory(prefix="clearfills_ta_") as tmp_dir:
        firewall = FirewallService.from_data_dir(data_dir=Path(tmp_dir), policy=policy, initialize_armed=True, ttl_seconds=120)
        for raw in ta_decisions:
            proposal = from_tradingagents_decision(raw)
            decision = firewall.propose(proposal, portfolio)
            print(f"{proposal.symbol:5s} | {decision.status.value:8s} | codes={decision.reason_codes}")
            if decision.approved and decision.attestation is not None:
                queued = queue_to_approval_inbox(proposal, decision, api_key=api_key, dry_run=dry_run)
                print(f"      -> Ed25519 attested ({decision.attestation.attestation_id}), inbox={queued.get('status', queued.get('id'))}")
        assert firewall.verify_audit().valid


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Gate TradingAgents output with ClearFills firewall + 1-Tap Inbox.")
    parser.add_argument("--dry-run", action="store_true", help="Preview firewall attestation and inbox payload locally.")
    args = parser.parse_args()
    run(dry_run=args.dry_run or not os.environ.get("CLEARFILLS_API_KEY", "").strip())
