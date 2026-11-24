"""Safe execution wrapper for virattt/ai-hedge-fund using clearfills-firewall.

Demonstrates how to route multi-analyst portfolio decisions from
`virattt/ai-hedge-fund` through the ClearFills deterministic risk firewall,
apply per-sleeve rules (active equities vs. T-bill cash equivalents), and
optionally queue approved proposals into the ClearFills Cloud 1-Tap Approval
Inbox for human sign-off before IBKR or Alpaca execution.

Run locally (offline mode, zero credentials required):
    pip install clearfills-firewall
    python examples/ai_hedge_fund_safe_execution.py

Optional Cloud 1-Tap Approval Inbox queuing:
    export CLEARFILLS_API_KEY="cf_sk_..."
    python examples/ai_hedge_fund_safe_execution.py
"""

from __future__ import annotations

import json
import os
import tempfile
import urllib.error
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
    from_ai_hedge_fund_signal,
)

DEFAULT_CLOUD_API_URL = "https://clearfills-api.fly.dev"


def queue_for_one_tap_approval(
    proposal: TradeProposal,
    decision: RiskDecision,
    *,
    api_key: str,
    api_url: str = DEFAULT_CLOUD_API_URL,
) -> dict[str, Any]:
    """Queue an attested proposal in the ClearFills Cloud 1-Tap Approval Inbox."""
    if not decision.approved or decision.attestation is None:
        raise ValueError("Only firewall-approved proposals with an attestation can be queued")

    notional_usd = round((proposal.limit_price or 0.0) * proposal.quantity, 2)
    payload: dict[str, Any] = {
        "symbol": proposal.symbol,
        "side": proposal.side.value,
        "quantity": proposal.quantity,
        "order_type": proposal.order_type.value,
        "limit_price": proposal.limit_price,
        "stop_price": proposal.stop_price,
        "target_price": proposal.target_price,
        "notional_usd": notional_usd,
        "attestation_id": decision.attestation.attestation_id,
        "proposal_id": proposal.proposal_id,
        "agent_id": proposal.agent_id,
        "venue": proposal.venue,
        "sleeve": decision.metrics.get("sleeve", "active_trading"),
        "reasoning_trace": proposal.reasoning_trace,
    }

    req = urllib.request.Request(
        url=f"{api_url.rstrip('/')}/api/v1/cloud/approvals",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "clearfills-example/0.4",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10.0) as resp:
        return json.loads(resp.read().decode("utf-8"))


def mock_ai_hedge_fund_decisions() -> list[dict[str, Any]]:
    """Representative portfolio manager decisions from virattt/ai-hedge-fund."""
    return [
        {
            "ticker": "AAPL",
            "action": "buy",
            "quantity": 50,
            "confidence": 74,
            "limit_price": 200.00,
            "stop_price": 190.00,
            "target_price": 225.00,
            "venue": "alpaca",
            "reasoning": "Consistent free cash flow and strong services retention.",
            "analyst_signals": {
                "fundamentals_agent": {
                    "signal": "bullish",
                    "confidence": 78,
                    "reasoning": "Operating margins stable with disciplined buybacks.",
                },
                "valuation_agent": {
                    "signal": "bullish",
                    "confidence": 70,
                    "reasoning": "Trades within historical DCF fair value band.",
                },
            },
        },
        {
            "ticker": "SGOV",
            "action": "buy",
            "quantity": 200,
            "confidence": 95,
            "limit_price": 100.50,
            "stop_price": None,  # Exempt in cash_equivalent sleeve
            "venue": "ibkr",
            "reasoning": "Park idle settled cash in short-duration US T-bills.",
            "analyst_signals": {
                "treasury_agent": {
                    "signal": "bullish",
                    "confidence": 95,
                    "reasoning": "Idle cash exceeds operating liquidity buffer.",
                },
            },
        },
        {
            "ticker": "NVDA",
            "action": "buy",
            "quantity": 500,
            "confidence": 82,
            "limit_price": 140.00,  # $70,000 notional exceeds $50,000 active cap
            "stop_price": 120.00,   # $10,000 risk exceeds 1% NAV ($1,000)
            "venue": "alpaca",
            "reasoning": "High momentum breakout candidate.",
        },
    ]


def main() -> None:
    portfolio = PortfolioSnapshot(
        account_id="DU1234567",
        nav_usd=100_000.0,
        cash_usd=50_000.0,
        daily_pnl_usd=0.0,
        session_entries=0,
        open_positions=[],
    )

    policy = RiskPolicy(
        max_risk_per_trade_pct=1.0,
        max_open_positions=10,
        max_total_heat_pct=8.0,
        max_daily_loss_pct=2.0,
        require_stop_loss=True,
        max_order_notional_usd=50_000.0,
        sleeves=default_allocation_sleeves(),
    )

    api_key = os.environ.get("CLEARFILLS_API_KEY", "").strip()
    api_url = os.environ.get("CLEARFILLS_API_URL", DEFAULT_CLOUD_API_URL).strip()

    with tempfile.TemporaryDirectory(prefix="clearfills_ahf_") as tmp_dir:
        firewall = FirewallService.from_data_dir(
            data_dir=Path(tmp_dir),
            policy=policy,
            initialize_armed=True,
            ttl_seconds=120,
        )

        for raw_signal in mock_ai_hedge_fund_decisions():
            proposal = from_ai_hedge_fund_signal(raw_signal)
            decision = firewall.propose(proposal, portfolio)
            sleeve = decision.metrics.get("sleeve", "active_trading")

            print(
                f"{proposal.symbol:5s} | sleeve={sleeve:15s} | "
                f"status={decision.status.value:8s} | codes={decision.reason_codes}"
            )

            if decision.approved and decision.attestation is not None:
                if api_key:
                    try:
                        queued = queue_for_one_tap_approval(
                            proposal,
                            decision,
                            api_key=api_key,
                            api_url=api_url,
                        )
                        print(f"      -> queued in ClearFills Inbox: {queued.get('id', queued)}")
                    except urllib.error.URLError as exc:
                        print(f"      -> failed to queue in ClearFills Cloud: {exc}")
                else:
                    print(
                        f"      -> attested ({decision.attestation.attestation_id}); "
                        "set CLEARFILLS_API_KEY to queue in ClearFills 1-Tap Inbox"
                    )

        audit = firewall.verify_audit()
        print(f"\nAudit chain valid={audit.valid} entries={audit.entry_count}")
        assert audit.valid


if __name__ == "__main__":
    main()
